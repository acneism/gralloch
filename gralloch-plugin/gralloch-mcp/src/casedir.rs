//! Case creation and the on-disk `case.json` state file (stage 0).
//!
//! The sample is stored as `sample/<sha256>.bin` (NO executable extension) and
//! marked read-only. This is the deterministic half of the isolation guarantee
//! (tz-re-pipeline.md 4.3); the PreToolUse hook is the tripwire on top of it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::hashes;

const SCHEMA_VERSION: &str = "0.1.0";
const PROFILES: [&str; 4] = ["understand", "malware", "vuln", "ctf"];

#[derive(Debug, Serialize, Deserialize)]
pub struct HashesJson {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolVersions {
    pub gralloch_mcp: String,
    pub ghidra: String,
    pub capa: String,
    pub yara_rules: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Isolation {
    /// Intended VM network mode. The user/skill must verify it before dynamics.
    pub network: String,
    /// Whether a clean VM snapshot has been confirmed (user asserts this).
    pub snapshot_confirmed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseJson {
    pub schema_version: String,
    pub profile: String,
    /// Current pipeline stage (0..=7).
    pub stage: u8,
    pub hashes: HashesJson,
    pub original_name: String,
    pub original_ext: String,
    /// Path to the stored sample, relative to the case dir: `sample/<sha256>.bin`.
    pub stored_sample: String,
    pub size: u64,
    pub tool_versions: ToolVersions,
    pub isolation: Isolation,
}

pub struct CaseNewResult {
    pub summary: String,
}

/// Create a new case under `cases_root` from the file at `sample_path`.
pub fn case_new(sample_path: &str, cases_root: &str, profile: &str) -> Result<CaseNewResult> {
    if !PROFILES.contains(&profile) {
        bail!("unknown profile '{profile}'; expected one of {PROFILES:?}");
    }

    let src = Path::new(sample_path);
    let bytes = fs::read(src).with_context(|| format!("reading sample {sample_path}"))?;
    if bytes.is_empty() {
        bail!("sample {sample_path} is empty");
    }
    let h = hashes::compute(&bytes);

    let original_name = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    let original_ext = src
        .extension()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Case id = first 16 hex chars of sha256 (collision-safe enough for a folder).
    let case_id = &h.sha256[..16];
    let case_dir = Path::new(cases_root).join(case_id);
    let sample_dir = case_dir.join("sample");
    let artifacts_dir = case_dir.join("artifacts");
    fs::create_dir_all(&sample_dir).with_context(|| format!("creating {}", sample_dir.display()))?;
    fs::create_dir_all(&artifacts_dir)
        .with_context(|| format!("creating {}", artifacts_dir.display()))?;

    // Store WITHOUT an executable extension, then mark read-only.
    let stored_rel = format!("sample/{}.bin", h.sha256);
    let stored_path = sample_dir.join(format!("{}.bin", h.sha256));
    fs::write(&stored_path, &bytes)
        .with_context(|| format!("writing stored sample {}", stored_path.display()))?;
    set_readonly(&stored_path)?;

    let network = if profile == "malware" {
        "disabled-or-fakenet (REQUIRED for malware; verify in VM)".to_string()
    } else {
        "host-only (verify before any dynamics)".to_string()
    };

    let case = CaseJson {
        schema_version: SCHEMA_VERSION.to_string(),
        profile: profile.to_string(),
        stage: 0,
        hashes: HashesJson {
            md5: h.md5.clone(),
            sha1: h.sha1.clone(),
            sha256: h.sha256.clone(),
        },
        original_name,
        original_ext,
        stored_sample: stored_rel.clone(),
        size: bytes.len() as u64,
        tool_versions: ToolVersions {
            gralloch_mcp: env!("CARGO_PKG_VERSION").to_string(),
            ghidra: "unknown".into(),
            capa: "unknown".into(),
            yara_rules: "none".into(),
        },
        isolation: Isolation {
            network,
            snapshot_confirmed: false,
        },
    };
    write_case_json(&case_dir, &case)?;
    write_notes_template(&case_dir, &case)?;

    let summary = format!(
        "Case created: {dir}\n  profile: {profile}   stage: 0\n  sha256:  {sha}\n  stored:  {rel} (read-only, non-executable)\nNext: run triage with case_dir = \"{dir}\"",
        dir = case_dir.display(),
        profile = profile,
        sha = h.sha256,
        rel = stored_rel,
    );
    Ok(CaseNewResult { summary })
}

pub fn case_json_path(case_dir: &Path) -> PathBuf {
    case_dir.join("case.json")
}

pub fn read_case_json(case_dir: &Path) -> Result<CaseJson> {
    let p = case_json_path(case_dir);
    let data = fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
    let case: CaseJson =
        serde_json::from_slice(&data).with_context(|| format!("parsing {}", p.display()))?;
    Ok(case)
}

pub fn write_case_json(case_dir: &Path, case: &CaseJson) -> Result<()> {
    let p = case_json_path(case_dir);
    let json = serde_json::to_string_pretty(case)?;
    fs::write(&p, json).with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

fn write_notes_template(case_dir: &Path, case: &CaseJson) -> Result<()> {
    let p = case_dir.join("notes.md");
    if p.exists() {
        return Ok(());
    }
    let body = format!(
        "# Notes — {id}\n\n\
         Profile: {profile}\n\
         sha256: {sha}\n\n\
         ## Hypotheses\n\
         <!-- id | statement | source(static/string/guess) | status(hypothesis/confirmed/rejected) | evidence -->\n\n\
         ## Confirmed\n\
         (only what dynamic analysis verified)\n\n\
         ## IOCs\n",
        id = &case.hashes.sha256[..16],
        profile = case.profile,
        sha = case.hashes.sha256,
    );
    fs::write(&p, body).with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

#[cfg(windows)]
fn set_readonly(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(windows))]
fn set_readonly(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // r--r--r--
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    Ok(())
}
