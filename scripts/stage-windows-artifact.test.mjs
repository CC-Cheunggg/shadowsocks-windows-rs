import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  stageWindowsArtifact,
  verifyStagedArtifact,
} from "./stage-windows-artifact.mjs";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "sswr-artifact-test-"));
  const repositoryRoot = join(root, "repository");
  const releaseDirectory = join(root, "release");
  const nsisDirectory = join(root, "nsis");
  const stageDirectory = join(root, "stage");
  mkdirSync(join(repositoryRoot, "src-tauri/resources/wintun"), {
    recursive: true,
  });
  mkdirSync(releaseDirectory, { recursive: true });
  mkdirSync(nsisDirectory, { recursive: true });

  const files = new Map([
    [join(releaseDirectory, "shadowsocks-windows-rs.exe"), "main"],
    [join(releaseDirectory, "network_recover.exe"), "recover"],
    [join(releaseDirectory, "wintun_smoke.exe"), "smoke"],
    [join(releaseDirectory, "wintun.dll"), "approved-wintun"],
    [join(repositoryRoot, "LICENSE"), "project-license"],
    [join(repositoryRoot, "THIRD_PARTY_NOTICES.md"), "third-party"],
    [
      join(
        repositoryRoot,
        "src-tauri/resources/wintun/WINTUN-LICENSE.txt",
      ),
      "wintun-license",
    ],
    [join(nsisDirectory, "Shadowsocks_0.1.0_x64-setup.exe"), "setup"],
  ]);
  for (const [path, contents] of files) {
    writeFileSync(path, contents);
  }

  return {
    root,
    repositoryRoot,
    releaseDirectory,
    nsisDirectory,
    stageDirectory,
    metadata: {
      projectVersion: "0.1.0-test",
      tauriCliVersion: "2.test",
      commit: "LOCAL-SIMULATION-NOT-ACTIONS-EVIDENCE",
      ref: "refs/heads/local-simulation",
      refName: "local-simulation",
      runId: "LOCAL-SIMULATION",
      runAttempt: "LOCAL-SIMULATION",
      rustcVersion: "rustc LOCAL-SIMULATION",
      nodeVersion: "node LOCAL-SIMULATION",
      npmVersion: "npm LOCAL-SIMULATION",
    },
    expectedWintunHash: sha256("approved-wintun"),
    expectedWintunLicenseHash: sha256("wintun-license"),
  };
}

function withFixture(callback) {
  const current = fixture();
  try {
    callback(current);
  } finally {
    rmSync(current.root, { recursive: true, force: true });
  }
}

test("stages the exact delivery inventory and verifies every staged hash", () => {
  withFixture((current) => {
    const result = stageWindowsArtifact(current);
    verifyStagedArtifact(current.stageDirectory, result.setupName);
    const manifest = readFileSync(
      join(current.stageDirectory, "SHA256SUMS"),
      "ascii",
    );
    assert.match(manifest, /  BUILD-INFO\n/u);
    assert.match(manifest, /  Shadowsocks_0\.1\.0_x64-setup\.exe\n/u);
    assert.doesNotMatch(manifest, /  SHA256SUMS\n/u);
    assert.match(
      readFileSync(join(current.stageDirectory, "BUILD-INFO"), "utf8"),
      /webview2_install_mode=downloadBootstrapper\n/u,
    );
  });
});

test("rejects zero or multiple NSIS setup files", () => {
  withFixture((current) => {
    rmSync(join(current.nsisDirectory, "Shadowsocks_0.1.0_x64-setup.exe"));
    assert.throws(
      () => stageWindowsArtifact(current),
      /expected exactly one \*-setup\.exe.*found 0/u,
    );
  });
  withFixture((current) => {
    writeFileSync(join(current.nsisDirectory, "Other-setup.exe"), "other");
    assert.throws(
      () => stageWindowsArtifact(current),
      /expected exactly one \*-setup\.exe.*found 2/u,
    );
  });
});

test("rejects a missing input and a non-empty stage", () => {
  withFixture((current) => {
    rmSync(join(current.releaseDirectory, "network_recover.exe"));
    assert.throws(
      () => stageWindowsArtifact(current),
      /required input network_recover\.exe is missing/u,
    );
  });
  withFixture((current) => {
    mkdirSync(current.stageDirectory);
    writeFileSync(join(current.stageDirectory, "unexpected.bin"), "unexpected");
    assert.throws(
      () => stageWindowsArtifact(current),
      /stage directory is not empty/u,
    );
  });
});

test("rejects tampering, extra files, and incomplete manifests", () => {
  withFixture((current) => {
    const { setupName } = stageWindowsArtifact(current);
    writeFileSync(join(current.stageDirectory, "wintun.dll"), "tampered");
    assert.throws(
      () => verifyStagedArtifact(current.stageDirectory, setupName),
      /staged SHA-256 mismatch for wintun\.dll/u,
    );
  });
  withFixture((current) => {
    const { setupName } = stageWindowsArtifact(current);
    writeFileSync(join(current.stageDirectory, "unexpected.bin"), "unexpected");
    assert.throws(
      () => verifyStagedArtifact(current.stageDirectory, setupName),
      /artifact inventory differs/u,
    );
  });
  withFixture((current) => {
    const { setupName } = stageWindowsArtifact(current);
    const manifestPath = join(current.stageDirectory, "SHA256SUMS");
    const lines = readFileSync(manifestPath, "ascii").split("\n");
    writeFileSync(manifestPath, `${lines.slice(1, -1).join("\n")}\n`, "ascii");
    assert.throws(
      () => verifyStagedArtifact(current.stageDirectory, setupName),
      /SHA256SUMS inventory differs/u,
    );
  });
});
