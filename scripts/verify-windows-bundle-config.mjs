import { readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  HASHED_STATIC_DELIVERY_NAMES,
  STATIC_DELIVERY_NAMES,
} from "./stage-windows-artifact.mjs";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptsDirectory, "..");
const tauriDirectory = resolve(repositoryRoot, "src-tauri");

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function fail(message) {
  throw new Error(`Windows bundle configuration check failed: ${message}`);
}

const baseConfig = readJson(resolve(tauriDirectory, "tauri.conf.json"));
const windowsConfig = readJson(
  resolve(tauriDirectory, "tauri.windows.conf.json"),
);
const windowsConfigText = readFileSync(
  resolve(tauriDirectory, "tauri.windows.conf.json"),
  "utf8",
);
const workflowText = readFileSync(
  resolve(repositoryRoot, ".github/workflows/windows.yml"),
  "utf8",
);

if (baseConfig.bundle?.active !== true) {
  fail("bundle.active must be true.");
}

const targets = baseConfig.bundle?.targets;
if (
  !Array.isArray(targets) ||
  targets.length !== 1 ||
  targets[0] !== "nsis"
) {
  fail('bundle.targets must be exactly ["nsis"].');
}

const webviewInstallMode =
  windowsConfig.bundle?.windows?.webviewInstallMode;
if (webviewInstallMode?.type !== "downloadBootstrapper") {
  fail(
    "bundle.windows.webviewInstallMode.type must be downloadBootstrapper.",
  );
}
if (webviewInstallMode.silent !== true) {
  fail("the downloaded WebView2 bootstrapper must run silently.");
}
if (
  Object.keys(webviewInstallMode).sort().join(",") !== "silent,type"
) {
  fail("webviewInstallMode may contain only type and silent.");
}
if (/offlineInstaller|fixedRuntime/i.test(windowsConfigText)) {
  fail("offlineInstaller and fixedRuntime are prohibited.");
}
if (
  /MicrosoftEdgeWebView2RuntimeInstaller|WebView2.*(?:path|installer)/i.test(
    windowsConfigText,
  )
) {
  fail("a local WebView2 installer or runtime path is prohibited.");
}

const requiredResources = new Map([
  ["resources/wintun/amd64/wintun.dll", "wintun.dll"],
  ["../LICENSE", "LICENSE.txt"],
  ["../THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"],
  ["../third_party/wintun/LICENSE.txt", "WINTUN-LICENSE.txt"],
]);
const configuredResources = windowsConfig.bundle?.resources;
if (
  configuredResources === null ||
  typeof configuredResources !== "object" ||
  Array.isArray(configuredResources)
) {
  fail("bundle.resources must be a source-to-destination map.");
}
const configuredResourceSources = Object.keys(configuredResources).sort();
const expectedResourceSources = [...requiredResources.keys()].sort();
if (
  JSON.stringify(configuredResourceSources) !==
  JSON.stringify(expectedResourceSources)
) {
  fail("bundle.resources must contain only the four approved explicit files.");
}

for (const [source, destination] of requiredResources) {
  if (configuredResources[source] !== destination) {
    fail(`resource ${source} must be mapped to ${destination}.`);
  }

  const sourcePath = resolve(tauriDirectory, source);
  if (!statSync(sourcePath).isFile()) {
    fail(`resource source is not a file: ${sourcePath}`);
  }
}

const requiredWorkflowFragments = [
  "cargo build --manifest-path src-tauri/Cargo.toml --locked --release --bins --target x86_64-pc-windows-msvc --features custom-protocol",
  "npm run tauri -- bundle --target x86_64-pc-windows-msvc --bundles nsis --ci --features custom-protocol",
  "scripts/stage-windows-artifact.mjs",
  "--release-dir $release",
  "$env:SSWR_RUSTC_VERSION = (rustc --version)",
  "$env:SSWR_NPM_VERSION = (npm --version)",
  "actions/upload-artifact@v7",
  "if-no-files-found: error",
];
for (const fragment of requiredWorkflowFragments) {
  if (!workflowText.includes(fragment)) {
    fail(`Windows workflow is missing required fragment: ${fragment}`);
  }
}
if (/offlineInstaller|fixedRuntime|verify-nsis-offline/i.test(workflowText)) {
  fail("Windows workflow still contains offline or fixed WebView2 logic.");
}

const expectedStaticNames = [
  "BUILD-INFO",
  "LICENSE.txt",
  "THIRD_PARTY_NOTICES.md",
  "WINTUN-LICENSE.txt",
  "network_recover.exe",
  "shadowsocks-windows-rs.exe",
  "wintun.dll",
  "wintun_smoke.exe",
].sort();
if (
  JSON.stringify(STATIC_DELIVERY_NAMES) !==
  JSON.stringify(expectedStaticNames)
) {
  fail("the required static artifact inventory is inconsistent.");
}
if (
  JSON.stringify(HASHED_STATIC_DELIVERY_NAMES) !==
  JSON.stringify(STATIC_DELIVERY_NAMES)
) {
  fail("SHA256SUMS does not cover every required static delivery file.");
}

console.log(
  "Verified NSIS downloadBootstrapper mode, raw-EXE delivery, and artifact inventory.",
);
