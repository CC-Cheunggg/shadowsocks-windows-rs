//! Windows packet-capture and route ownership boundary.
//!
//! Platform-independent callers may compile these modules on non-Windows
//! hosts. Operations that would touch Wintun or the Windows route table return
//! an explicit unsupported-platform error there.

pub mod network_change;
pub mod routes;
pub mod wintun;
