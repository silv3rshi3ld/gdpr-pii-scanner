//! Self-contained HTML reports for offline review.

use crate::core::{GdprCategory, ScanResults};
use crate::reporter::write_private_file;
use std::fmt::Write as _;
use std::io;
use std::path::Path;

pub struct HtmlReporter {
    overwrite: bool,
}

impl HtmlReporter {
    pub fn new() -> Self {
        Self { overwrite: false }
    }

    pub fn overwrite(mut self, enabled: bool) -> Self {
        self.overwrite = enabled;
        self
    }

    pub fn write_to_file(&self, results: &ScanResults, output_path: &Path) -> io::Result<()> {
        write_private_file(
            output_path,
            self.generate_html(results).as_bytes(),
            self.overwrite,
        )
    }

    pub fn generate_html(&self, results: &ScanResults) -> String {
        let mut rows = String::new();
        for file in &results.files {
            for finding in &file.matches {
                let category = match &finding.gdpr_category {
                    GdprCategory::Regular => "regular".to_string(),
                    GdprCategory::Special { category, .. } => {
                        format!("special: {category}")
                    }
                };
                let context = finding
                    .context
                    .as_ref()
                    .and_then(|context| context.redacted_snippet.as_deref())
                    .unwrap_or("");
                let _ = write!(
                    rows,
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}:{}</td><td>{}</td><td>{}</td></tr>",
                    escape_html(&finding.location.file_path.to_string_lossy()),
                    escape_html(&finding.detector_name),
                    escape_html(&finding.country.to_uppercase()),
                    escape_html(&finding.value_masked),
                    escape_html(&finding.severity.to_string()),
                    escape_html(&finding.confidence.to_string()),
                    finding.location.line,
                    finding.location.column,
                    escape_html(&category),
                    escape_html(context),
                );
            }
        }

        let findings = if rows.is_empty() {
            let message = if results.error_count == 0 && results.truncated_files == 0 {
                "No reportable findings."
            } else {
                "No findings were reported, but the scan was incomplete."
            };
            format!("<p class=\"empty\">{message}</p>")
        } else {
            format!(
                "<div class=\"table-wrap\"><table><thead><tr><th>Source</th><th>Detector</th><th>Country</th><th>Masked value</th><th>Severity</th><th>Confidence</th><th>Location</th><th>Category</th><th>Redacted context</th></tr></thead><tbody>{rows}</tbody></table></div>"
            )
        };

        let mut issue_rows = String::new();
        for file in &results.files {
            if file.error.is_none() && !file.truncated {
                continue;
            }
            let issue = match (&file.error, file.truncated) {
                (Some(error), true) => format!(
                    "{}; results truncated, at least {} match(es) omitted",
                    error, file.omitted_matches
                ),
                (Some(error), false) => error.clone(),
                (None, true) => format!(
                    "results truncated, at least {} match(es) omitted",
                    file.omitted_matches
                ),
                (None, false) => unreachable!(),
            };
            let _ = write!(
                issue_rows,
                "<tr><td><code>{}</code></td><td>{}</td></tr>",
                escape_html(&file.path.to_string_lossy()),
                escape_html(&issue),
            );
        }
        let issues = if issue_rows.is_empty() {
            String::new()
        } else {
            format!(
                "<h2>Incomplete sources</h2><div class=\"table-wrap\"><table><thead><tr><th>Source</th><th>Issue</th></tr></thead><tbody>{issue_rows}</tbody></table></div>"
            )
        };

        format!(
            r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PII Radar scan report</title>
<style>
:root{{--ink:#17202a;--muted:#5f6b76;--line:#d8dee4;--surface:#f6f8fa;--accent:#315c9b}}
*{{box-sizing:border-box}} body{{max-width:1200px;margin:0 auto;padding:2rem;font:15px/1.5 system-ui,sans-serif;color:var(--ink)}}
h1{{margin-bottom:.2rem}} .meta{{color:var(--muted);margin-top:0}} .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin:2rem 0}}
.card{{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:1rem}} .value{{display:block;font-size:1.6rem;font-weight:650}} .label{{color:var(--muted)}}
.notice{{border-left:4px solid var(--accent);background:var(--surface);padding:.8rem 1rem}} .table-wrap{{overflow:auto}} table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid var(--line);padding:.55rem;text-align:left;vertical-align:top}} th{{background:var(--surface)}} code{{white-space:pre-wrap;overflow-wrap:anywhere}} .empty{{padding:2rem;background:var(--surface)}}
</style>
</head>
<body>
<header><h1>PII Radar scan report</h1><p class="meta">Schema {} · Tool {} · Target {}</p></header>
<section class="cards" aria-label="Scan summary">
<div class="card"><span class="value">{}</span><span class="label">Status</span></div>
<div class="card"><span class="value">{}</span><span class="label">Sources</span></div>
<div class="card"><span class="value">{}</span><span class="label">Matches</span></div>
<div class="card"><span class="value">{}</span><span class="label">Errors</span></div>
<div class="card"><span class="value">{}</span><span class="label">Omitted matches</span></div>
<div class="card"><span class="value">{} ms</span><span class="label">Duration</span></div>
</section>
<p class="notice">Candidate findings require review. This report does not establish legal compliance or prove the absence of personal data.</p>
<h2>Findings</h2>
{}
{}
</body>
</html>
"#,
            escape_html(&results.schema_version),
            escape_html(&results.tool_version),
            escape_html(&format!("{:?}", results.target_kind)),
            escape_html(&format!("{:?}", results.status)),
            results.total_files,
            results.total_matches,
            results.error_count,
            results.omitted_matches,
            results.total_time_ms,
            findings,
            issues,
        )
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            character => escaped.push(character),
        }
    }
    escaped
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Confidence, FileResult, GdprCategory, Location, Match, Severity};
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn empty_report_is_factual() {
        let html = HtmlReporter::new().generate_html(&ScanResults::new());
        assert!(html.contains("No reportable findings"));
        assert!(html.contains("does not establish legal compliance"));
    }

    #[test]
    fn untrusted_fields_are_html_escaped() {
        let mut file = FileResult::new(PathBuf::from("<source>"));
        file.matches.push(Match {
            detector_id: "test".to_string(),
            detector_name: "<script>alert(1)</script>".to_string(),
            country: "xx".to_string(),
            value_masked: "***".to_string(),
            location: Location::from_byte_span(PathBuf::from("<source>"), "x", 0, 1),
            confidence: Confidence::High,
            severity: Severity::High,
            context: None,
            gdpr_category: GdprCategory::Regular,
        });
        let html = HtmlReporter::new().generate_html(&ScanResults::aggregate(vec![file]));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert"));
    }

    #[test]
    fn reports_source_errors_and_only_redacted_context() {
        let mut file = FileResult::with_error(
            PathBuf::from("<failed>"),
            "could not read <secret>".to_string(),
        );
        file.truncated = true;
        file.omitted_matches = 2;
        let html = HtmlReporter::new().generate_html(&ScanResults::aggregate(vec![file]));
        assert!(html.contains("Incomplete sources"));
        assert!(html.contains("&lt;failed&gt;"));
        assert!(html.contains("could not read &lt;secret&gt;"));
        assert!(html.contains("at least 2 match(es) omitted"));
    }

    #[test]
    fn writes_report_and_refuses_replacement() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("report.html");
        let reporter = HtmlReporter::new();
        reporter.write_to_file(&ScanResults::new(), &path).unwrap();
        assert!(reporter.write_to_file(&ScanResults::new(), &path).is_err());
    }
}
