use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

const DNS_HEADER_LEN: usize = 12;
const MAX_QUESTIONS: usize = 16;
const MAX_ANSWERS: usize = 256;
const MAX_POINTER_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub domain: String,
    pub address: IpAddr,
    pub ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    name: String,
    record_type: u16,
    class: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    transaction_id: u16,
    questions: Vec<DnsQuestion>,
}

impl DnsQuery {
    pub fn transaction_id(&self) -> u16 {
        self.transaction_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMessageError {
    TooShort,
    NotQuery,
    NotResponse,
    InvalidCounts,
    InvalidName,
    TruncatedRecord,
    TruncatedResponse,
    ResponseCode(u8),
    TransactionMismatch,
    QuestionMismatch,
}

impl fmt::Display for DnsMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => formatter.write_str("DNS message is too short"),
            Self::NotQuery => formatter.write_str("DNS message is not a query"),
            Self::NotResponse => formatter.write_str("DNS message is not a response"),
            Self::InvalidCounts => formatter.write_str("DNS section count exceeds the safe limit"),
            Self::InvalidName => formatter.write_str("DNS name encoding is invalid"),
            Self::TruncatedRecord => formatter.write_str("DNS record is truncated"),
            Self::TruncatedResponse => formatter.write_str("DNS response is truncated"),
            Self::ResponseCode(code) => write!(formatter, "DNS response returned RCODE {code}"),
            Self::TransactionMismatch => {
                formatter.write_str("DNS response transaction does not match the request")
            }
            Self::QuestionMismatch => {
                formatter.write_str("DNS response question does not match the request")
            }
        }
    }
}

impl std::error::Error for DnsMessageError {}

/// Extracts the bounded identity needed to associate a future response. The
/// query wire payload is not retained.
pub fn parse_query(message: &[u8]) -> Result<DnsQuery, DnsMessageError> {
    let header = parse_header(message)?;
    if header.flags & 0x8000 != 0 {
        return Err(DnsMessageError::NotQuery);
    }
    let (questions, _) = parse_questions(message, header.question_count)?;
    Ok(DnsQuery {
        transaction_id: header.transaction_id,
        questions,
    })
}

/// Verifies transaction ID and the complete normalized question section before
/// a response is associated with a captured query.
pub fn response_correlates(message: &[u8], query: &DnsQuery) -> Result<(), DnsMessageError> {
    let header = parse_header(message)?;
    if header.flags & 0x8000 == 0 {
        return Err(DnsMessageError::NotResponse);
    }
    if header.transaction_id != query.transaction_id {
        return Err(DnsMessageError::TransactionMismatch);
    }
    let (questions, _) = parse_questions(message, header.question_count)?;
    if questions != query.questions {
        return Err(DnsMessageError::QuestionMismatch);
    }
    Ok(())
}

/// Parses cacheable records only after request/response association succeeds.
pub fn parse_response_answers_for_query(
    message: &[u8],
    query: &DnsQuery,
) -> Result<Vec<DnsAnswer>, DnsMessageError> {
    response_correlates(message, query)?;
    parse_response_answers(message)
}

/// Extracts only bounded A/AAAA metadata. The input payload is never retained.
pub fn parse_response_answers(message: &[u8]) -> Result<Vec<DnsAnswer>, DnsMessageError> {
    let header = parse_header(message)?;
    if header.flags & 0x8000 == 0 {
        return Err(DnsMessageError::NotResponse);
    }
    if header.flags & 0x0200 != 0 {
        return Err(DnsMessageError::TruncatedResponse);
    }
    let response_code = (header.flags & 0x000f) as u8;
    if response_code != 0 {
        return Err(DnsMessageError::ResponseCode(response_code));
    }

    let (questions, mut offset) = parse_questions(message, header.question_count)?;

    let mut direct = Vec::new();
    let mut aliases = HashMap::<String, (String, u32)>::new();
    for _ in 0..header.answer_count {
        let (owner, next) = parse_name(message, offset)?;
        offset = next;
        require(message, offset, 10)?;
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let ttl = u32::from_be_bytes(
            message[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| DnsMessageError::TruncatedRecord)?,
        );
        let data_len = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        offset += 10;
        require(message, offset, data_len)?;
        if class == 1 {
            match (record_type, data_len) {
                (1, 4) => direct.push((
                    owner,
                    IpAddr::V4(Ipv4Addr::new(
                        message[offset],
                        message[offset + 1],
                        message[offset + 2],
                        message[offset + 3],
                    )),
                    ttl,
                )),
                (28, 16) => {
                    let octets: [u8; 16] = message[offset..offset + 16]
                        .try_into()
                        .map_err(|_| DnsMessageError::TruncatedRecord)?;
                    direct.push((owner, IpAddr::V6(Ipv6Addr::from(octets)), ttl));
                }
                (5, _) => {
                    let (canonical, canonical_end) = parse_name(message, offset)?;
                    if canonical_end != offset + data_len {
                        return Err(DnsMessageError::TruncatedRecord);
                    }
                    aliases.insert(owner, (canonical, ttl));
                }
                _ => {}
            }
        }
        offset += data_len;
    }

    let mut answers = Vec::new();
    for (owner, address, ttl) in direct {
        answers.push(DnsAnswer {
            domain: owner.clone(),
            address,
            ttl: Duration::from_secs(u64::from(ttl)),
        });
        for question in &questions {
            if let Some(ttl) = resolution_ttl(&question.name, &owner, ttl, &aliases) {
                answers.push(DnsAnswer {
                    domain: question.name.clone(),
                    address,
                    ttl: Duration::from_secs(u64::from(ttl)),
                });
            }
        }
    }
    answers.sort_by(|left, right| {
        left.domain
            .cmp(&right.domain)
            .then_with(|| left.address.cmp(&right.address))
    });
    answers.dedup();
    Ok(answers)
}

#[derive(Debug, Clone, Copy)]
struct DnsHeader {
    transaction_id: u16,
    flags: u16,
    question_count: usize,
    answer_count: usize,
}

fn parse_header(message: &[u8]) -> Result<DnsHeader, DnsMessageError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(DnsMessageError::TooShort);
    }
    let question_count = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answer_count = usize::from(u16::from_be_bytes([message[6], message[7]]));
    if question_count == 0 || question_count > MAX_QUESTIONS || answer_count > MAX_ANSWERS {
        return Err(DnsMessageError::InvalidCounts);
    }
    Ok(DnsHeader {
        transaction_id: u16::from_be_bytes([message[0], message[1]]),
        flags: u16::from_be_bytes([message[2], message[3]]),
        question_count,
        answer_count,
    })
}

fn parse_questions(
    message: &[u8],
    question_count: usize,
) -> Result<(Vec<DnsQuestion>, usize), DnsMessageError> {
    let mut offset = DNS_HEADER_LEN;
    let mut questions = Vec::with_capacity(question_count);
    for _ in 0..question_count {
        let (name, next) = parse_name(message, offset)?;
        offset = next;
        require(message, offset, 4)?;
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        offset += 4;
        questions.push(DnsQuestion {
            name,
            record_type,
            class,
        });
    }
    Ok((questions, offset))
}

fn resolution_ttl(
    question: &str,
    owner: &str,
    address_ttl: u32,
    aliases: &HashMap<String, (String, u32)>,
) -> Option<u32> {
    let mut current = question;
    let mut seen = HashSet::new();
    let mut ttl = address_ttl;
    for _ in 0..MAX_POINTER_DEPTH {
        if current == owner {
            return Some(ttl);
        }
        if !seen.insert(current.to_owned()) {
            return None;
        }
        let Some((next, alias_ttl)) = aliases.get(current) else {
            return None;
        };
        ttl = ttl.min(*alias_ttl);
        current = next;
    }
    None
}

fn parse_name(message: &[u8], start: usize) -> Result<(String, usize), DnsMessageError> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut return_offset = None;
    let mut seen = HashSet::new();
    for _ in 0..MAX_POINTER_DEPTH {
        let length = *message.get(offset).ok_or(DnsMessageError::InvalidName)?;
        if length & 0xc0 == 0xc0 {
            let second = *message
                .get(offset + 1)
                .ok_or(DnsMessageError::InvalidName)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, second]));
            if pointer >= message.len() || !seen.insert(pointer) {
                return Err(DnsMessageError::InvalidName);
            }
            return_offset.get_or_insert(offset + 2);
            offset = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsMessageError::InvalidName);
        }
        offset += 1;
        if length == 0 {
            let name = labels.join(".").to_ascii_lowercase();
            validate_domain(&name)?;
            return Ok((name, return_offset.unwrap_or(offset)));
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(DnsMessageError::InvalidName);
        }
        require(message, offset, length)?;
        let label = std::str::from_utf8(&message[offset..offset + length])
            .map_err(|_| DnsMessageError::InvalidName)?;
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(DnsMessageError::InvalidName);
        }
        labels.push(label);
        offset += length;
    }
    Err(DnsMessageError::InvalidName)
}

fn validate_domain(domain: &str) -> Result<(), DnsMessageError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(DnsMessageError::InvalidName);
    }
    Ok(())
}

fn require(message: &[u8], offset: usize, length: usize) -> Result<(), DnsMessageError> {
    if offset
        .checked_add(length)
        .is_some_and(|end| end <= message.len())
    {
        Ok(())
    } else {
        Err(DnsMessageError::TruncatedRecord)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> Vec<u8> {
        let mut message = vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        // www.example.com CNAME example.com
        message.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 2, 0xc0, 0x10]);
        // example.com A 192.0.2.1
        message.extend_from_slice(&[0xc0, 0x10, 0, 1, 0, 1, 0, 0, 0, 20, 0, 4, 192, 0, 2, 1]);
        message
    }

    fn query() -> Vec<u8> {
        let mut message = response();
        message[2..4].copy_from_slice(&0x0100_u16.to_be_bytes());
        message[6..8].copy_from_slice(&0_u16.to_be_bytes());
        message.truncate(33);
        message
    }

    #[test]
    fn extracts_bounded_a_records_and_follows_cname() {
        let answers = parse_response_answers(&response()).unwrap();
        assert!(answers.iter().any(|answer| {
            answer.domain == "example.com"
                && answer.address == "192.0.2.1".parse::<IpAddr>().unwrap()
        }));
        assert!(answers.iter().any(|answer| {
            answer.domain == "www.example.com"
                && answer.address == "192.0.2.1".parse::<IpAddr>().unwrap()
                && answer.ttl == Duration::from_secs(20)
        }));
    }

    #[test]
    fn cname_ttl_caps_the_cached_alias_lifetime() {
        let mut response = response();
        response[39..43].copy_from_slice(&10_u32.to_be_bytes());
        let answers = parse_response_answers(&response).unwrap();
        assert!(answers.iter().any(|answer| {
            answer.domain == "www.example.com" && answer.ttl == Duration::from_secs(10)
        }));
    }

    #[test]
    fn rejects_queries_pointer_loops_and_excessive_counts() {
        let mut query = response();
        query[2] &= 0x7f;
        assert_eq!(
            parse_response_answers(&query).unwrap_err(),
            DnsMessageError::NotResponse
        );

        let mut looped = response();
        looped[12] = 0xc0;
        looped[13] = 0x0c;
        assert_eq!(
            parse_response_answers(&looped).unwrap_err(),
            DnsMessageError::InvalidName
        );

        let mut excessive = response();
        excessive[6..8].copy_from_slice(&257_u16.to_be_bytes());
        assert_eq!(
            parse_response_answers(&excessive).unwrap_err(),
            DnsMessageError::InvalidCounts
        );
    }

    #[test]
    fn response_requires_matching_transaction_and_question() {
        let query = parse_query(&query()).unwrap();
        assert_eq!(query.transaction_id(), 0x1234);
        let answers = parse_response_answers_for_query(&response(), &query).unwrap();
        assert!(!answers.is_empty());

        let mut wrong_id = response();
        wrong_id[0..2].copy_from_slice(&0x4321_u16.to_be_bytes());
        assert_eq!(
            response_correlates(&wrong_id, &query).unwrap_err(),
            DnsMessageError::TransactionMismatch
        );

        let mut wrong_question = response();
        wrong_question[15] = b'x';
        assert_eq!(
            response_correlates(&wrong_question, &query).unwrap_err(),
            DnsMessageError::QuestionMismatch
        );
    }

    #[test]
    fn truncated_and_error_responses_are_not_cacheable() {
        let query = parse_query(&query()).unwrap();
        let mut truncated = response();
        truncated[2] |= 0x02;
        assert_eq!(
            parse_response_answers_for_query(&truncated, &query).unwrap_err(),
            DnsMessageError::TruncatedResponse
        );

        let mut nxdomain = response();
        nxdomain[3] = (nxdomain[3] & 0xf0) | 3;
        assert_eq!(
            parse_response_answers_for_query(&nxdomain, &query).unwrap_err(),
            DnsMessageError::ResponseCode(3)
        );
    }

    #[test]
    fn parser_does_not_confuse_responses_with_queries() {
        assert_eq!(
            parse_query(&response()).unwrap_err(),
            DnsMessageError::NotQuery
        );
        assert_eq!(
            parse_response_answers(&query()).unwrap_err(),
            DnsMessageError::NotResponse
        );
    }
}
