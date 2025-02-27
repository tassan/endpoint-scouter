"""
HTML reporter for EndpointScouter.
"""

import logging
from typing import Dict, List, Any

from endpoint_scouter.core.result import ScanResult, ScanSummary

logger = logging.getLogger("EndpointScouter")


class HtmlReporter:
    """Generates HTML reports from scan results."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the reporter.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.dbz_mode = config.get("dbz_mode", False)

    def generate(self, results: List[ScanResult], output_file: str) -> str:
        """
        Generate an HTML report.

        Args:
            results: List of scan results
            output_file: Output file path

        Returns:
            str: Path to the generated report
        """
        try:
            # Create summary
            summary = ScanSummary(results)

            # Get security score
            security_score = self._calculate_security_score(results)
            score_class = self._get_score_class(security_score)

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

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise

    def _get_score_class(self, score: str) -> str:
        """
        Get CSS class based on score value.

        Args:
            score: Score string

        Returns:
            str: CSS class
        """
        try:
            score_value = float(score.split()[0])

            if score_value >= 5000:
                return "good"
            elif score_value >= 3000:
                return "medium"
            else:
                return "bad"
        except (ValueError, IndexError):
            return "medium"

    def _calculate_security_score(self, results: List[ScanResult]) -> str:
        """
        Calculate security score based on results.

        Args:
            results: List of scan results

        Returns:
            str: Security score with message
        """
        if not results:
            return "0 - No results to score"

        total_score = 0
        max_score_per_endpoint = 9000

        for result in results:
            endpoint_score = 0

            # Points for security headers
            endpoint_score += len(result.security_headers) * 500

            # Points for CORS configuration
            if result.cors_headers:
                origin_header = result.cors_headers.get("Access-Control-Allow-Origin")
                if origin_header and origin_header != "*":
                    endpoint_score += 1500  # Restrictive CORS
                else:
                    endpoint_score += 500  # CORS configured, but permissive

            # Points for rate limiting
            if result.rate_limit_detected:
                endpoint_score += 2000

            # Deduct points for issues
            endpoint_score -= len(result.issues) * 300

            # Deduct points for vulnerabilities
            if result.vulnerabilities:
                endpoint_score -= (
                    sum(1 for v in result.vulnerabilities.values() if v) * 1000
                )

            # Limit maximum endpoint score
            endpoint_score = max(0, min(endpoint_score, max_score_per_endpoint))
            total_score += endpoint_score

        # Average score
        avg_score = total_score / len(results)

        # Return score with appropriate message based on mode
        if self.dbz_mode:
            if avg_score >= 8000:
                return f"{avg_score:.0f} - IT'S OVER 8000! Super Saiyan level security!"
            elif avg_score >= 6000:
                return f"{avg_score:.0f} - Super Saiyan: Excellent security implementation!"
            elif avg_score >= 5000:
                return f"{avg_score:.0f} - Elite Saiyan: Very good security measures"
            elif avg_score >= 3000:
                return f"{avg_score:.0f} - Saiyan Warrior: Good foundation but room for improvement"
            elif avg_score >= 1000:
                return (
                    f"{avg_score:.0f} - Trained Human: Basic security measures present"
                )
            else:
                return f"{avg_score:.0f} - Ordinary Human... serious security improvements needed!"
        else:
            if avg_score >= 8000:
                return f"{avg_score:.0f} - Excellent. Comprehensive security measures implemented."
            elif avg_score >= 6000:
                return f"{avg_score:.0f} - Very Good. Strong security implementation."
            elif avg_score >= 5000:
                return f"{avg_score:.0f} - Good. Strong security foundation present."
            elif avg_score >= 3000:
                return f"{avg_score:.0f} - Moderate. Basic security measures in place."
            elif avg_score >= 1000:
                return f"{avg_score:.0f} - Fair. Minimal security protections detected."
            else:
                return f"{avg_score:.0f} - Inadequate. Security improvements strongly recommended."
