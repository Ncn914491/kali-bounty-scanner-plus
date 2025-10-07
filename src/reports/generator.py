"""HackerOne-ready report generator."""

import json
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from integrations.gemini_client import GeminiClient
from utils.logger import log_info, log_error


class ReportGenerator:
    """Generate professional vulnerability reports."""
    
    def __init__(self, config):
        """
        Initialize report generator.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.gemini_client = GeminiClient(config)
        self.template_dir = Path(__file__).parent / 'templates'
        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))
    
    def generate(self, run_id, target, findings, output_dir):
        """
        Generate HackerOne-ready report.
        
        Args:
            run_id (str): Run identifier
            target (str): Target domain
            findings (list): List of triaged findings
            output_dir (Path): Output directory
        
        Returns:
            str: Path to generated report
        """
        log_info(f"Generating report for {target}")
        
        # Filter to high-confidence findings
        significant_findings = [
            f for f in findings
            if f.get('final_score', 0) > 0.5 and not f.get('is_false_positive', False)
        ]
        
        # Group by severity
        by_severity = self._group_by_severity(significant_findings)
        
        # Generate report for each high-value finding
        reports = []
        for finding in significant_findings[:10]:  # Top 10 findings
            report = self._generate_finding_report(finding, target)
            reports.append(report)
        
        # Generate summary report
        summary_report = self._generate_summary_report(
            run_id, target, significant_findings, by_severity
        )
        
        # Save reports
        output_dir = Path(output_dir)
        
        # Save individual finding reports
        findings_dir = output_dir / 'findings'
        findings_dir.mkdir(exist_ok=True)
        
        for i, report in enumerate(reports):
            report_file = findings_dir / f"finding_{i+1}.md"
            with open(report_file, 'w') as f:
                f.write(report)
        
        # Save summary
        summary_file = output_dir / 'report.md'
        with open(summary_file, 'w') as f:
            f.write(summary_report)
        
        log_info(f"Report saved to {summary_file}")
        
        return str(summary_file)
    
    def _generate_finding_report(self, finding, target):
        """
        Generate report for a single finding.
        
        Args:
            finding (dict): Finding data
            target (str): Target domain
        
        Returns:
            str: Markdown report
        """
        try:
            template = self.env.get_template('hackerone_report.md.j2')
        except Exception as e:
            log_error(f"Failed to load template: {e}")
            return self._generate_simple_report(finding, target)
        
        # Prepare data
        data = {
            'title': finding.get('name', 'Security Finding'),
            'target': target,
            'severity': finding.get('severity_adjusted', finding.get('severity', 'medium')),
            'description': finding.get('description', ''),
            'impact': self._generate_impact(finding),
            'reproduction_steps': self._generate_reproduction_steps(finding),
            'evidence': finding.get('evidence', {}),
            'remediation': self._generate_remediation(finding),
            'score': finding.get('final_score', 0),
            'confidence': finding.get('confidence', 0),
            'explanation': finding.get('explanation', ''),
            'date': datetime.now().strftime('%Y-%m-%d')
        }
        
        report = template.render(**data)
        
        # Polish with Gemini if available
        if self.gemini_client.enabled:
            try:
                polished = self.gemini_client.polish_report(report)
                return polished
            except Exception as e:
                log_error(f"Report polishing failed: {e}")
        
        return report
    
    def _generate_summary_report(self, run_id, target, findings, by_severity):
        """
        Generate summary report.
        
        Args:
            run_id (str): Run ID
            target (str): Target
            findings (list): All findings
            by_severity (dict): Findings grouped by severity
        
        Returns:
            str: Markdown summary
        """
        report = f"""# Security Assessment Report

**Target:** {target}
**Date:** {datetime.now().strftime('%Y-%m-%d')}
**Run ID:** {run_id}

## Executive Summary

This report contains the results of an automated security assessment conducted on {target}.
The assessment identified {len(findings)} significant findings requiring attention.

## Findings Summary

"""
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = len(by_severity.get(severity, []))
            if count > 0:
                report += f"- **{severity.upper()}**: {count} finding(s)\n"
        
        report += "\n## Detailed Findings\n\n"
        
        for i, finding in enumerate(findings[:10], 1):
            report += f"### {i}. {finding.get('name', 'Unknown')}\n\n"
            report += f"**Severity:** {finding.get('severity_adjusted', 'unknown').upper()}\n\n"
            report += f"**Confidence Score:** {finding.get('final_score', 0):.2f}\n\n"
            report += f"**Description:** {finding.get('description', 'N/A')}\n\n"
            report += f"**Location:** {finding.get('matched_at', finding.get('target', 'N/A'))}\n\n"
            report += "---\n\n"
        
        report += """## Methodology

This assessment used automated tools with AI-powered triage to identify potential security issues.
All findings have been scored and filtered to reduce false positives.

## Recommendations

1. Review and validate each finding manually
2. Prioritize remediation based on severity and confidence scores
3. Implement security controls to prevent similar issues
4. Conduct regular security assessments

## Disclaimer

This is an automated assessment. Manual verification is recommended before reporting to bug bounty programs.
"""
        
        return report
    
    def _generate_impact(self, finding):
        """Generate impact description."""
        severity = finding.get('severity', 'unknown').lower()
        
        impact_map = {
            'critical': 'This vulnerability could lead to complete system compromise, data breach, or significant business impact.',
            'high': 'This vulnerability could allow unauthorized access to sensitive data or functionality.',
            'medium': 'This vulnerability could expose information or allow limited unauthorized actions.',
            'low': 'This issue has minimal security impact but should be addressed.',
            'info': 'This is an informational finding that may aid in further attacks.'
        }
        
        return impact_map.get(severity, 'Impact assessment required.')
    
    def _generate_reproduction_steps(self, finding):
        """Generate reproduction steps."""
        steps = [
            f"1. Navigate to {finding.get('matched_at', finding.get('target', 'target URL'))}",
            "2. Observe the security issue as described",
            "3. Review the evidence provided below"
        ]
        
        return '\n'.join(steps)
    
    def _generate_remediation(self, finding):
        """Generate remediation suggestions."""
        name = finding.get('name', '').lower()
        
        if 'xss' in name or 'cross-site scripting' in name:
            return "Implement proper input validation and output encoding. Use Content-Security-Policy headers."
        elif 'sql' in name:
            return "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
        elif 'csrf' in name:
            return "Implement CSRF tokens for all state-changing operations."
        elif 'authentication' in name or 'auth' in name:
            return "Review authentication logic and ensure proper access controls are in place."
        elif 'header' in name:
            return "Configure security headers according to OWASP recommendations."
        else:
            return "Review the specific vulnerability and implement appropriate security controls."
    
    def _group_by_severity(self, findings):
        """Group findings by severity."""
        by_severity = {}
        
        for finding in findings:
            severity = finding.get('severity_adjusted', finding.get('severity', 'unknown')).lower()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        return by_severity
    
    def _generate_simple_report(self, finding, target):
        """Generate simple report without template."""
        return f"""# {finding.get('name', 'Security Finding')}

**Target:** {target}
**Severity:** {finding.get('severity', 'unknown').upper()}
**Date:** {datetime.now().strftime('%Y-%m-%d')}

## Description

{finding.get('description', 'No description available')}

## Evidence

```json
{json.dumps(finding.get('evidence', {}), indent=2)}
```

## Score

- ML Score: {finding.get('ml_score', 0):.2f}
- LLM Score: {finding.get('llm_score', 0):.2f}
- Final Score: {finding.get('final_score', 0):.2f}
- Confidence: {finding.get('confidence', 0):.2f}

## Explanation

{finding.get('explanation', 'No explanation available')}
"""
