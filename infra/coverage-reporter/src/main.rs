use clap::Parser;
use cpp_demangle::Symbol;
use std::{collections::BTreeMap, io, path::PathBuf};
use tokio::process::Command;

use fuzzor_infra::{get_harness_binary, FuzzEngine, Language, ProjectConfig, Sanitizer};

const PROFRAW_FILE: &str = "default.profraw";
const PROFDATA_FILE: &str = "default.profdata";
const COVERAGE_SUMMARY_FILE: &str = "coverage-summary.json";
const COVERED_FUNCTIONS_FILE: &str = "/workdir/covered-functions.txt";
const FUNCTION_COUNTS_FILE: &str = "/workdir/function-counts.json";
const LINE_COVERAGE_FILE: &str = "/workdir/line-coverage.json";
const COVERAGE_REPORT_DIR: &str = "/workdir/coverage_report";

#[derive(Parser, Debug)]
struct Options {
    #[arg(help = "Path to project config", required = true)]
    pub config: PathBuf,
    #[arg(help = "Corpus to report coverage for", required = true)]
    pub corpus: String,
    #[arg(help = "Name of the harness to report coverage for", required = true)]
    pub harness: String,
}

fn demangle_name(mangled: &str) -> String {
    Symbol::new(mangled.as_bytes())
        .ok()
        .and_then(|s| s.demangle().ok())
        .unwrap_or_else(|| mangled.to_string())
}

struct CoverageReporter {
    binary_path: PathBuf,
    demangler: Option<String>,
}

impl CoverageReporter {
    fn new(binary_path: PathBuf, language: &Language) -> Self {
        let demangler = match language {
            Language::Rust => Some("rustfilt".to_string()),
            Language::Cpp => Some("c++filt".to_string()),
            _ => None,
        };
        Self {
            binary_path,
            demangler,
        }
    }

    async fn run_coverage_binary(&self, corpus_path: &str) -> io::Result<()> {
        let status = Command::new(&self.binary_path)
            .arg("-runs=1")
            .arg(corpus_path)
            .kill_on_drop(true)
            .status()
            .await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Coverage binary execution failed",
            ));
        }
        Ok(())
    }

    async fn merge_profdata(&self) -> io::Result<()> {
        let status = Command::new("llvm-profdata")
            .args(["merge", "-sparse", PROFRAW_FILE, "-o", PROFDATA_FILE])
            .kill_on_drop(true)
            .status()
            .await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to merge profdata",
            ));
        }
        Ok(())
    }

    async fn export_coverage_summary(&self) -> io::Result<()> {
        let coverage_summary_file = std::fs::File::create(COVERAGE_SUMMARY_FILE)?;

        let status = Command::new("llvm-cov")
            .args([
                "export",
                self.binary_path.to_str().unwrap(),
                "-summary-only",
                &format!("-instr-profile={}", PROFDATA_FILE),
            ])
            .kill_on_drop(true)
            .stdout(coverage_summary_file)
            .status()
            .await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to export coverage summary",
            ));
        }
        Ok(())
    }

    async fn export_covered_functions(&self) -> io::Result<()> {
        let output = Command::new("llvm-cov")
            .args([
                "export",
                self.binary_path.to_str().unwrap(),
                &format!("-instr-profile={}", PROFDATA_FILE),
            ])
            .kill_on_drop(true)
            .output()
            .await?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to export full coverage data",
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut function_counts: BTreeMap<String, i64> = BTreeMap::new();

        if let Some(functions) = json["data"][0]["functions"].as_array() {
            for func in functions {
                let count = func["count"].as_i64().unwrap_or(0);
                if count > 0 {
                    if let Some(name) = func["name"].as_str() {
                        let demangled = demangle_name(name);
                        function_counts
                            .entry(demangled)
                            .and_modify(|c| *c += count)
                            .or_insert(count);
                    }
                }
            }
        }

        let covered_functions_contents = function_counts
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        tokio::fs::write(COVERED_FUNCTIONS_FILE, covered_functions_contents).await?;

        let function_counts_json = serde_json::to_vec_pretty(&function_counts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(FUNCTION_COUNTS_FILE, function_counts_json).await?;

        // line-coverage.json: filename -> {line: count} for covered lines only.
        // Per-line count is the max across column-segments on that line; zero-count
        // segments (uncovered regions) and gaps are dropped since they are noise for
        // PR-impact matching.
        let mut line_coverage: BTreeMap<String, BTreeMap<i64, i64>> = BTreeMap::new();

        if let Some(files) = json["data"][0]["files"].as_array() {
            for file in files {
                let filename = match file["filename"].as_str() {
                    Some(f) => f,
                    None => continue,
                };
                let segments = match file["segments"].as_array() {
                    Some(s) => s,
                    None => continue,
                };

                let mut lines: BTreeMap<i64, i64> = BTreeMap::new();
                for seg in segments {
                    let seg = match seg.as_array() {
                        Some(s) => s,
                        None => continue,
                    };
                    // segments: [line, col, count, hasCount, isGap]
                    if seg.len() < 5 {
                        continue;
                    }
                    let has_count = seg[3].as_bool().unwrap_or(false);
                    let is_gap = seg[4].as_bool().unwrap_or(false);
                    if !has_count || is_gap {
                        continue;
                    }
                    let count = seg[2].as_i64().unwrap_or(0);
                    if count <= 0 {
                        continue;
                    }
                    let line = seg[0].as_i64().unwrap_or(0);
                    lines
                        .entry(line)
                        .and_modify(|c| *c = (*c).max(count))
                        .or_insert(count);
                }

                if !lines.is_empty() {
                    line_coverage.insert(filename.to_string(), lines);
                }
            }
        }

        let line_coverage_json = serde_json::to_vec_pretty(&line_coverage)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(LINE_COVERAGE_FILE, line_coverage_json).await?;

        Ok(())
    }

    async fn generate_html_report(&self) -> io::Result<()> {
        let mut cmd = Command::new("llvm-cov");
        cmd.args([
            "show",
            self.binary_path.to_str().unwrap(),
            &format!("-instr-profile={}", PROFDATA_FILE),
            "-format=html",
            "-show-directory-coverage",
            "-show-branches=count",
            &format!("-output-dir={}", COVERAGE_REPORT_DIR),
        ]);

        if let Some(demangler) = &self.demangler {
            cmd.arg(format!("-Xdemangler={}", demangler));
        }

        let status = cmd.kill_on_drop(true).status().await?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to generate HTML report",
            ));
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let opts = Options::parse();

    let config = tokio::fs::read_to_string(&opts.config).await?;
    let config: ProjectConfig =
        serde_yaml::from_str(&config).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let coverage_bin = get_harness_binary(
        &FuzzEngine::None,
        &Sanitizer::Coverage,
        &opts.harness,
        &config,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get harness binary"))?;

    let reporter = CoverageReporter::new(coverage_bin, &config.language);

    reporter.run_coverage_binary(&opts.corpus).await?;
    reporter.merge_profdata().await?;
    reporter.export_coverage_summary().await?;
    reporter.export_covered_functions().await?;
    reporter.generate_html_report().await?;

    Ok(())
}
