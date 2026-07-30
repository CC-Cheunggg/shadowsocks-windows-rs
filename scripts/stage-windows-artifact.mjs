import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultRepositoryRoot = resolve(scriptDirectory, "..");
const HASH_MANIFEST_NAME = "SHA256SUMS";

const DELIVERY_INPUTS = Object.freeze([
  ["release/shadowsocks-windows-rs.exe", "shadowsocks-windows-rs.exe"],
  ["release/network_recover.exe", "network_recover.exe"],
  ["release/wintun_smoke.exe", "wintun_smoke.exe"],
  ["release/wintun.dll", "wintun.dll"],
  ["repository/LICENSE", "LICENSE.txt"],
  ["repository/THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"],
  [
    "repository/src-tauri/resources/wintun/WINTUN-LICENSE.txt",
    "WINTUN-LICENSE.txt",
  ],
]);

export const STATIC_DELIVERY_NAMES = Object.freeze(
  [...DELIVERY_INPUTS.map(([, destination]) => destination), "BUILD-INFO"].sort(),
);
export const HASHED_STATIC_DELIVERY_NAMES = Object.freeze(
  [...STATIC_DELIVERY_NAMES],
);

function fail(message) {
  throw new Error(`Windows artifact check failed: ${message}`);
}

function sorted(values) {
  return [...values].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function assertSafeFilename(name) {
  if (
    !name ||
    name === "." ||
    name === ".." ||
    name.startsWith(".") ||
    name.includes("/") ||
    name.includes("\\") ||
    /[\u0000-\u001f<>:"|?*]/u.test(name)
  ) {
    fail(`unsafe artifact filename: ${JSON.stringify(name)}`);
  }
}

function sha256File(path) {
  const hash = createHash("sha256");
  const bytes = readFileSync(path);
  hash.update(bytes);
  return hash.digest("hex");
}

function requireFile(path, label) {
  if (!existsSync(path) || !statSync(path).isFile()) {
    fail(`${label} is missing or is not a file: ${path}`);
  }
}

function listStageFiles(stageDirectory) {
  return sorted(
    readdirSync(stageDirectory, { withFileTypes: true }).map((entry) => {
      if (!entry.isFile()) {
        fail(`artifact root contains a non-file entry: ${entry.name}`);
      }
      assertSafeFilename(entry.name);
      return entry.name;
    }),
  );
}

function compareNames(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      `${label} differs; expected [${expected.join(", ")}], got [${actual.join(", ")}]`,
    );
  }
}

function discoverSetup(nsisDirectory) {
  if (!existsSync(nsisDirectory) || !statSync(nsisDirectory).isDirectory()) {
    fail(`NSIS output directory is missing: ${nsisDirectory}`);
  }
  const setups = readdirSync(nsisDirectory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /-setup\.exe$/iu.test(entry.name))
    .map((entry) => entry.name);
  if (setups.length !== 1) {
    fail(
      `expected exactly one *-setup.exe in the NSIS output directory, found ${setups.length}`,
    );
  }
  assertSafeFilename(setups[0]);
  return setups[0];
}

function sanitizeBuildValue(name, value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    /[\r\n\u0000]/u.test(value)
  ) {
    fail(`BUILD-INFO value ${name} is missing or invalid`);
  }
  return value;
}

function buildInfoText(metadata, setupName, setupHash) {
  const fields = [
    ["project", "shadowsocks-windows-rs"],
    ["project_version", metadata.projectVersion],
    ["tauri_cli_version", metadata.tauriCliVersion],
    ["commit", metadata.commit],
    ["ref", metadata.ref],
    ["ref_name", metadata.refName],
    ["github_run_id", metadata.runId],
    ["github_run_attempt", metadata.runAttempt],
    ["target", "x86_64-pc-windows-msvc"],
    ["profile", "release"],
    ["rustc", metadata.rustcVersion],
    ["node", metadata.nodeVersion],
    ["npm", metadata.npmVersion],
    ["bundle", "nsis"],
    ["nsis_setup", setupName],
    ["nsis_setup_sha256", setupHash],
    ["webview2_install_mode", "downloadBootstrapper"],
    ["webview2_installer_silent", "true"],
    ["bare_exe_webview2_bootstrap", "enabled"],
    ["msvc_crt", "static"],
    ["main_pe_subsystem", "2"],
    ["network_recover_pe_subsystem", "3"],
    ["wintun_smoke_pe_subsystem", "3"],
  ];
  return `${fields
    .map(([name, value]) => `${name}=${sanitizeBuildValue(name, value)}`)
    .join("\n")}\n`;
}

function parseManifest(text) {
  if (!text.endsWith("\n") || text.includes("\r")) {
    fail("SHA256SUMS must use LF line endings and end with a newline");
  }
  const entries = new Map();
  for (const line of text.slice(0, -1).split("\n")) {
    const match = /^([0-9a-f]{64})  ([^\r\n]+)$/u.exec(line);
    if (!match) {
      fail(`invalid SHA256SUMS line: ${JSON.stringify(line)}`);
    }
    const [, hash, name] = match;
    assertSafeFilename(name);
    if (name === HASH_MANIFEST_NAME) {
      fail("SHA256SUMS must not hash itself");
    }
    const key = name.toLocaleLowerCase("en-US");
    if (entries.has(key)) {
      fail(`duplicate SHA256SUMS filename: ${name}`);
    }
    entries.set(key, { name, hash });
  }
  return entries;
}

export function verifyStagedArtifact(stageDirectory, setupName) {
  assertSafeFilename(setupName);
  const expectedHashed = sorted([...HASHED_STATIC_DELIVERY_NAMES, setupName]);
  const expectedAll = sorted([...expectedHashed, HASH_MANIFEST_NAME]);
  compareNames(listStageFiles(stageDirectory), expectedAll, "artifact inventory");

  const manifestPath = join(stageDirectory, HASH_MANIFEST_NAME);
  const entries = parseManifest(readFileSync(manifestPath, "ascii"));
  const manifestNames = sorted([...entries.values()].map((entry) => entry.name));
  compareNames(manifestNames, expectedHashed, "SHA256SUMS inventory");

  for (const name of expectedHashed) {
    const entry = entries.get(name.toLocaleLowerCase("en-US"));
    if (!entry || entry.name !== name) {
      fail(`SHA256SUMS spelling mismatch for ${name}`);
    }
    const actualHash = sha256File(join(stageDirectory, name));
    if (actualHash !== entry.hash) {
      fail(`staged SHA-256 mismatch for ${name}`);
    }
  }
}

export function stageWindowsArtifact({
  repositoryRoot,
  releaseDirectory,
  nsisDirectory,
  stageDirectory,
  metadata,
  expectedWintunHash,
  expectedWintunLicenseHash,
}) {
  const setupName = discoverSetup(nsisDirectory);
  if (existsSync(stageDirectory)) {
    if (!statSync(stageDirectory).isDirectory()) {
      fail(`artifact stage path exists and is not a directory: ${stageDirectory}`);
    }
    if (readdirSync(stageDirectory).length !== 0) {
      fail(`artifact stage directory is not empty: ${stageDirectory}`);
    }
  } else {
    mkdirSync(stageDirectory, { recursive: true });
  }

  const inputs = [
    ...DELIVERY_INPUTS.map(([source, destination]) => {
      const [scope, ...parts] = source.split("/");
      const root = scope === "release" ? releaseDirectory : repositoryRoot;
      return [join(root, ...parts), destination];
    }),
    [join(nsisDirectory, setupName), setupName],
  ];
  for (const [source, destination] of inputs) {
    requireFile(source, `required input ${destination}`);
    copyFileSync(source, join(stageDirectory, destination));
  }

  const stagedSetup = join(stageDirectory, setupName);
  const setupHash = sha256File(stagedSetup);
  if (setupHash !== sha256File(join(nsisDirectory, setupName))) {
    fail("staged NSIS setup differs from its source");
  }
  const stagedWintunHash = sha256File(join(stageDirectory, "wintun.dll"));
  if (stagedWintunHash !== expectedWintunHash) {
    fail("staged wintun.dll does not match the approved SHA-256");
  }
  const stagedWintunLicenseHash = sha256File(
    join(stageDirectory, "WINTUN-LICENSE.txt"),
  );
  if (stagedWintunLicenseHash !== expectedWintunLicenseHash) {
    fail("staged Wintun license does not match the approved SHA-256");
  }

  writeFileSync(
    join(stageDirectory, "BUILD-INFO"),
    buildInfoText(metadata, setupName, setupHash),
    { encoding: "utf8" },
  );

  const expectedHashed = sorted([...HASHED_STATIC_DELIVERY_NAMES, setupName]);
  compareNames(listStageFiles(stageDirectory), expectedHashed, "pre-manifest inventory");
  const hashLines = expectedHashed.map(
    (name) => `${sha256File(join(stageDirectory, name))}  ${name}`,
  );
  writeFileSync(
    join(stageDirectory, HASH_MANIFEST_NAME),
    `${hashLines.join("\n")}\n`,
    { encoding: "ascii" },
  );

  verifyStagedArtifact(stageDirectory, setupName);
  return { setupName, stageDirectory };
}

function packageMetadata(repositoryRoot) {
  const packageJson = JSON.parse(
    readFileSync(join(repositoryRoot, "package.json"), "utf8"),
  );
  const packageLock = JSON.parse(
    readFileSync(join(repositoryRoot, "package-lock.json"), "utf8"),
  );
  const tauriCliVersion =
    packageLock.packages?.["node_modules/@tauri-apps/cli"]?.version;
  return {
    projectVersion: packageJson.version,
    tauriCliVersion,
  };
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined) {
      fail("expected --name value arguments");
    }
    if (values.has(flag)) {
      fail(`duplicate argument: ${flag}`);
    }
    values.set(flag, value);
  }
  return values;
}

function requireArgument(argumentsMap, name) {
  const value = argumentsMap.get(name);
  if (!value) {
    fail(`missing argument: ${name}`);
  }
  return resolve(value);
}

function actionsMetadata(repositoryRoot) {
  return {
    ...packageMetadata(repositoryRoot),
    commit: process.env.GITHUB_SHA,
    ref: process.env.GITHUB_REF,
    refName: process.env.GITHUB_REF_NAME,
    runId: process.env.GITHUB_RUN_ID,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT,
    rustcVersion: process.env.SSWR_RUSTC_VERSION,
    nodeVersion: process.version,
    npmVersion: process.env.SSWR_NPM_VERSION,
  };
}

function runCli() {
  const argumentsMap = parseArguments(process.argv.slice(2));
  const stageDirectory = requireArgument(argumentsMap, "--stage-dir");
  const verifyOnly = argumentsMap.get("--verify-only");
  if (verifyOnly !== undefined) {
    verifyStagedArtifact(stageDirectory, verifyOnly);
    console.log(`Verified staged Windows artifact: ${stageDirectory}`);
    return;
  }

  const repositoryRoot = argumentsMap.has("--repository-root")
    ? requireArgument(argumentsMap, "--repository-root")
    : defaultRepositoryRoot;
  const releaseDirectory = requireArgument(argumentsMap, "--release-dir");
  const nsisDirectory = requireArgument(argumentsMap, "--nsis-dir");

  const result = stageWindowsArtifact({
    repositoryRoot,
    releaseDirectory,
    nsisDirectory,
    stageDirectory,
    metadata: actionsMetadata(repositoryRoot),
    expectedWintunHash: sanitizeBuildValue(
      "WINTUN_DLL_SHA256",
      process.env.WINTUN_DLL_SHA256,
    ),
    expectedWintunLicenseHash: sanitizeBuildValue(
      "WINTUN_LICENSE_SHA256",
      process.env.WINTUN_LICENSE_SHA256,
    ),
  });
  console.log(`Staged and verified ${result.setupName} in ${result.stageDirectory}`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  runCli();
}
