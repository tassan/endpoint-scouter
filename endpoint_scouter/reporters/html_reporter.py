"""
HTML reporter for EndpointScouter.
"""

import os
import logging
from typing import Dict, List, Any

from endpoint_scouter.core.result import ScanResult, ScanSummary
from endpoint_scouter.utils.scoring import get_score_message, calculate_overall_score

logger = logging.getLogger("EndpointScouter")

# Define the reports directory
REPORTS_DIR = "reports"


class HtmlReporter:
    """Generates HTML reports from scan results."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the reporter."""
        self.config = config or {}
        self.dbz_mode = config.get("dbz_mode", False)

        # Ensure reports directory exists
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
            logger.info(f"Created reports directory: {REPORTS_DIR}")

    def generate(self, results: List[ScanResult], output_file: str) -> str:
        """Generate an HTML report."""
        try:
            # Create summary
            summary = ScanSummary(results)

            # Get security score
            score = calculate_overall_score(results)
            security_score = get_score_message(score, self.dbz_mode)
            score_class = self._get_score_class(score)

            html_content = self._generate_html_content(
                summary, results, security_score, score_class
            )

            # Ensure path exists with subfolder
            file_dir = os.path.join(
                REPORTS_DIR, os.path.splitext(os.path.basename(output_file))[0]
            )
            os.makedirs(file_dir, exist_ok=True)

            # Full path for the file
            file_path = os.path.join(file_dir, os.path.basename(output_file))

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise

    def _get_score_class(self, score: int) -> str:
        """Get CSS class based on score value."""
        if score >= 5000:
            return "good"
        elif score >= 3000:
            return "medium"
        else:
            return "bad"

    def _generate_html_content(self, summary, results, security_score, score_class):
        """Generate HTML content for the report."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>EndpointScouter Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .score {{ font-size: 24px; font-weight: bold; }}
                .good {{ color: green; }}
                .medium {{ color: orange; }}
                .bad {{ color: red; }}
                .summary-box {{ border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; }}
                .endpoint-row:hover {{ background-color: #f0f0f0; }}
                .issues-list {{ color: #d9534f; }}
            </style>
        </head>
        <body>
            <h1>{"🐉 EndpointScouter Power Level Report 🐉" if self.dbz_mode else "EndpointScouter Security Report"}</h1>
            <p>Scan Date: {summary.timestamp}</p>
            
            <div class="summary-box">
                <h2>Summary</h2>
                <p class="score {score_class}">
                    {"Power Level" if self.dbz_mode else "Security Score"}: {security_score}
                </p>
                <p>Total Endpoints: {summary.total_endpoints}</p>
                <p>Accessible Endpoints: {summary.accessible_endpoints}</p>
                <p>Endpoints with Issues: {summary.with_issues}</p>
                <p>Secure Endpoints: {summary.secure_endpoints}</p>
            </div>
            
            <h2>Domains Overview</h2>
            <table>
                <tr>
                    <th>Domain</th>
                    <th>Endpoints</th>
                    <th>Issues</th>
                    <th>Secure</th>
                </tr>
        """

        # Add domains
        for domain, data in summary.domains.items():
            html_content += f"""
                <tr>
                    <td>{domain}</td>
                    <td>{data['count']}</td>
                    <td>{data['issues']}</td>
                    <td>{data['secure']}</td>
                </tr>
            """

        html_content += """
            </table>
            
            <h2>Common Issues</h2>
            <table>
                <tr>
                    <th>Issue</th>
                    <th>Count</th>
                </tr>
        """

        # Add common issues
        for issue, count in summary.common_issues.items():
            html_content += f"""
                <tr>
                    <td>{issue}</td>
                    <td>{count}</td>
                </tr>
            """

        html_content += """
            </table>
            
            <h2>Endpoint Details</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>Security Headers</th>
                    <th>CORS</th>
                    <th>Rate Limit</th>
                    <th>Issues</th>
                </tr>
        """

        # Add endpoints
        for r in results:
            status_class = ""
            if r.status_code:
                if r.status_code < 400:
                    status_class = "good"
                elif r.status_code < 500:
                    status_class = "medium"
                else:
                    status_class = "bad"

            issues = "<br>".join(r.issues) if r.issues else "None"

            html_content += f"""
                <tr class="endpoint-row">
                    <td>{r.endpoint.url}</td>
                    <td>{r.endpoint.method}</td>
                    <td class="{status_class}">{r.status_code}</td>
                    <td>{len(r.security_headers)}</td>
                    <td>{"Yes" if r.cors_headers else "No"}</td>
                    <td>{"Yes" if r.rate_limit_detected else "No"}</td>
                    <td class="issues-list">{issues}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        return html_content
