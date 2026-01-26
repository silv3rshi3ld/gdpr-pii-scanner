/// HTML reporter with styled, interactive output
use crate::core::{GdprCategory, ScanResults, Severity};
use chrono::Local;
use std::fs;
use std::path::Path;
use tera::{Context, Tera};

pub struct HtmlReporter {
    template: String,
}

impl HtmlReporter {
    pub fn new() -> Self {
        Self {
            template: Self::default_template(),
        }
    }

    /// Generate HTML report and write to file
    pub fn write_to_file(&self, results: &ScanResults, output_path: &Path) -> std::io::Result<()> {
        let html = self.generate_html(results);
        fs::write(output_path, html)?;
        Ok(())
    }

    /// Generate HTML report as string
    pub fn generate_html(&self, results: &ScanResults) -> String {
        let mut tera = Tera::default();
        tera.add_raw_template("report.html", &self.template)
            .expect("Failed to parse template");

        let mut context = Context::new();

        // Basic statistics
        context.insert("total_files", &results.total_files);
        context.insert("total_matches", &results.total_matches);
        context.insert("total_time_ms", &results.total_time_ms);
        context.insert(
            "scan_date",
            &Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );

        // Extraction statistics
        context.insert("extracted_files", &results.extracted_files);
        context.insert("extraction_failures", &results.extraction_failures);

        // Severity breakdown
        context.insert("severity_critical", &results.by_severity.critical);
        context.insert("severity_high", &results.by_severity.high);
        context.insert("severity_medium", &results.by_severity.medium);
        context.insert("severity_low", &results.by_severity.low);

        // Files with matches
        let files_with_matches: Vec<_> = results
            .files
            .iter()
            .filter(|f| !f.matches.is_empty())
            .collect();

        // Prepare matches for template
        let mut all_matches = Vec::new();
        for file in &files_with_matches {
            for m in &file.matches {
                let severity_color = match m.severity {
                    Severity::Critical => "danger",
                    Severity::High => "warning",
                    Severity::Medium => "info",
                    Severity::Low => "secondary",
                };

                let gdpr_special = matches!(m.gdpr_category, GdprCategory::Special { .. });

                all_matches.push(serde_json::json!({
                    "file_path": file.path.display().to_string(),
                    "detector_name": m.detector_name,
                    "country": m.country.to_uppercase(),
                    "value_masked": m.value_masked,
                    "severity": format!("{:?}", m.severity),
                    "severity_color": severity_color,
                    "confidence": format!("{:?}", m.confidence),
                    "line": m.location.line,
                    "column": m.location.column,
                    "gdpr_special": gdpr_special,
                }));
            }
        }

        context.insert("matches", &all_matches);
        context.insert("files_with_pii", &files_with_matches.len());

        tera.render("report.html", &context)
            .expect("Failed to render template")
    }

    fn default_template() -> String {
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PII-Radar Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }
        .stat-label {
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .severity-breakdown {
            padding: 30px;
            background: white;
        }
        .severity-breakdown h2 {
            margin-bottom: 20px;
            color: #333;
        }
        .severity-bars {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .severity-bar {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .severity-label {
            min-width: 100px;
            font-weight: 600;
        }
        .bar-container {
            flex: 1;
            background: #e9ecef;
            border-radius: 20px;
            height: 30px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            padding: 0 10px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }
        .bar-critical { background: #dc3545; }
        .bar-high { background: #fd7e14; }
        .bar-medium { background: #ffc107; color: #333; }
        .bar-low { background: #6c757d; }
        .search-box {
            padding: 30px;
            background: white;
            border-bottom: 1px solid #dee2e6;
        }
        .search-input {
            width: 100%;
            padding: 15px 20px;
            font-size: 1em;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            transition: border-color 0.3s;
        }
        .search-input:focus {
            outline: none;
            border-color: #667eea;
        }
        .matches-table {
            padding: 30px;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            position: sticky;
            top: 0;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-danger { background: #dc3545; color: white; }
        .badge-warning { background: #fd7e14; color: white; }
        .badge-info { background: #0dcaf0; color: white; }
        .badge-secondary { background: #6c757d; color: white; }
        .gdpr-badge {
            background: #d63384;
            color: white;
            margin-left: 5px;
        }
        .code {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .footer {
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
            color: #6c757d;
            font-size: 0.9em;
        }
        .no-matches {
            padding: 60px;
            text-align: center;
            color: #6c757d;
        }
        .no-matches h3 {
            font-size: 1.5em;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 PII-Radar Scan Report</h1>
            <p>Scanned on {{ scan_date }}</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{ total_files }}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ files_with_pii }}</div>
                <div class="stat-label">Files with PII</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ total_matches }}</div>
                <div class="stat-label">PII Matches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ total_time_ms }}</div>
                <div class="stat-label">Scan Time (ms)</div>
            </div>
            {% if extracted_files > 0 %}
            <div class="stat-card">
                <div class="stat-value">{{ extracted_files }}</div>
                <div class="stat-label">Documents Extracted</div>
            </div>
            {% endif %}
        </div>

        {% if total_matches > 0 %}
        <div class="severity-breakdown">
            <h2>Severity Breakdown</h2>
            <div class="severity-bars">
                {% if severity_critical > 0 %}
                <div class="severity-bar">
                    <span class="severity-label">🔴 Critical</span>
                    <div class="bar-container">
                        <div class="bar-fill bar-critical" style="width: {{ severity_critical * 100 / total_matches }}%">
                            {{ severity_critical }}
                        </div>
                    </div>
                </div>
                {% endif %}
                {% if severity_high > 0 %}
                <div class="severity-bar">
                    <span class="severity-label">🟠 High</span>
                    <div class="bar-container">
                        <div class="bar-fill bar-high" style="width: {{ severity_high * 100 / total_matches }}%">
                            {{ severity_high }}
                        </div>
                    </div>
                </div>
                {% endif %}
                {% if severity_medium > 0 %}
                <div class="severity-bar">
                    <span class="severity-label">🟡 Medium</span>
                    <div class="bar-container">
                        <div class="bar-fill bar-medium" style="width: {{ severity_medium * 100 / total_matches }}%">
                            {{ severity_medium }}
                        </div>
                    </div>
                </div>
                {% endif %}
                {% if severity_low > 0 %}
                <div class="severity-bar">
                    <span class="severity-label">🔵 Low</span>
                    <div class="bar-container">
                        <div class="bar-fill bar-low" style="width: {{ severity_low * 100 / total_matches }}%">
                            {{ severity_low }}
                        </div>
                    </div>
                </div>
                {% endif %}
            </div>
        </div>

        <div class="search-box">
            <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search by file, detector, or country...">
        </div>

        <div class="matches-table">
            <table id="matchesTable">
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Detector</th>
                        <th>Country</th>
                        <th>Value</th>
                        <th>Severity</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                {% for match in matches %}
                    <tr>
                        <td><span class="code">{{ match.file_path }}</span></td>
                        <td>{{ match.detector_name }}</td>
                        <td>{{ match.country }}</td>
                        <td><span class="code">{{ match.value_masked }}</span></td>
                        <td>
                            <span class="badge badge-{{ match.severity_color }}">{{ match.severity }}</span>
                            {% if match.gdpr_special %}
                            <span class="badge gdpr-badge">GDPR Art.9</span>
                            {% endif %}
                        </td>
                        <td>Line {{ match.line }}:{{ match.column }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="no-matches">
            <h3>✅ No PII Found</h3>
            <p>Your scan completed successfully with no personally identifiable information detected.</p>
        </div>
        {% endif %}

        <div class="footer">
            <p>Generated by <strong>PII-Radar</strong> • High-performance PII scanner for GDPR compliance</p>
        </div>
    </div>

    <script>
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        const table = document.getElementById('matchesTable');
        
        if (searchInput && table) {
            searchInput.addEventListener('input', function() {
                const searchTerm = this.value.toLowerCase();
                const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
                
                for (let row of rows) {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                }
            });
        }
    </script>
</body>
</html>"#.to_string()
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FileResult, SeverityCounts};
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_html_reporter_create() {
        let reporter = HtmlReporter::new();
        assert!(!reporter.template.is_empty());
    }

    #[test]
    fn test_html_reporter_generate_empty() {
        let reporter = HtmlReporter::new();
        let results = ScanResults {
            files: vec![],
            total_files: 0,
            total_bytes: 0,
            total_matches: 0,
            total_time_ms: 100,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let html = reporter.generate_html(&results);
        assert!(html.contains("PII-Radar Scan Report"));
        assert!(html.contains("No PII Found"));
    }

    #[test]
    fn test_html_reporter_write_file() {
        let tmp = TempDir::new().unwrap();
        let output_path = tmp.path().join("report.html");

        let reporter = HtmlReporter::new();
        let results = ScanResults {
            files: vec![],
            total_files: 5,
            total_bytes: 0,
            total_matches: 0,
            total_time_ms: 150,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        assert!(reporter.write_to_file(&results, &output_path).is_ok());
        assert!(output_path.exists());

        // Verify content
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("PII-Radar Scan Report"));
        assert!(content.contains("5")); // total_files
    }

    #[test]
    fn test_html_reporter_with_matches() {
        let reporter = HtmlReporter::new();
        let mut file_result = FileResult::new(PathBuf::from("test.txt"));
        file_result.matches.push(crate::core::Match {
            detector_id: "test".to_string(),
            detector_name: "Test Detector".to_string(),
            country: "nl".to_string(),
            value_masked: "123****89".to_string(),
            severity: crate::core::Severity::Critical,
            confidence: crate::core::Confidence::High,
            location: crate::core::Location {
                file_path: PathBuf::from("test.txt"),
                line: 1,
                column: 5,
                start_byte: 0,
                end_byte: 9,
            },
            context: None,
            gdpr_category: GdprCategory::Regular,
        });

        let results = ScanResults {
            files: vec![file_result],
            total_files: 1,
            total_bytes: 100,
            total_matches: 1,
            total_time_ms: 50,
            by_severity: SeverityCounts {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
            },
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let html = reporter.generate_html(&results);
        assert!(html.contains("Test Detector"));
        assert!(html.contains("123****89"));
        assert!(html.contains("Critical"));
    }
}
