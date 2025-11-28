#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report Generator Module
Generates security vulnerability reports in various formats
"""

import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class ReportGenerator:
    """Generates security vulnerability reports"""

    def __init__(self):
        self.risk_level_emojis = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️'
        }

        self.risk_level_colors = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFAA00',
            'low': '#0066CC'
        }

    def generate_markdown_report(self, scan_data: Dict[str, Any], output_path: str):
        """Generate comprehensive markdown security report"""

        scan_info = scan_data['scan_info']
        vulnerabilities = scan_data['vulnerabilities']

        # Sort vulnerabilities by risk level and file
        vulnerabilities_sorted = sorted(
            vulnerabilities,
            key=lambda x: (self._risk_order(x['risk_level']), x['file_path'], x['line_number'])
        )

        # Generate report sections
        report_content = self._generate_header(scan_info)
        report_content += self._generate_executive_summary(scan_info, vulnerabilities_sorted)
        report_content += self._generate_risk_breakdown(scan_info)
        report_content += self._generate_detailed_findings(vulnerabilities_sorted)
        report_content += self._generate_remediation_summary(vulnerabilities_sorted)
        report_content += self._generate_compliance_assessment(scan_info)
        report_content += self._generate_appendix()

        # Write report to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

    def _risk_order(self, risk_level: str) -> int:
        """Get risk level order for sorting"""
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return order.get(risk_level.lower(), 4)

    def _generate_header(self, scan_info: Dict[str, Any]) -> str:
        """Generate report header"""
        return f"""# Java Security Vulnerability Assessment Report

**Generated on:** {self._format_datetime(scan_info['scan_time'])}
**Project Path:** `{scan_info['project_path']}`
**Scan Duration:** {scan_info['scan_duration']} seconds

---

"""

    def _generate_executive_summary(self, scan_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate executive summary"""
        total_vulns = len(vulnerabilities)
        risk_levels = scan_info['risk_levels']

        # Calculate risk score
        risk_score = (
            risk_levels['critical'] * 10 +
            risk_levels['high'] * 7 +
            risk_levels['medium'] * 4 +
            risk_levels['low'] * 1
        )

        # Determine overall risk rating
        if risk_score >= 50:
            overall_risk = "CRITICAL"
            risk_emoji = "🚨"
        elif risk_score >= 25:
            overall_risk = "HIGH"
            risk_emoji = "⚠️"
        elif risk_score >= 10:
            overall_risk = "MEDIUM"
            risk_emoji = "⚡"
        else:
            overall_risk = "LOW"
            risk_emoji = "ℹ️"

        # Most affected files
        file_counts = {}
        for vuln in vulnerabilities:
            file_path = vuln['file_path']
            file_counts[file_path] = file_counts.get(file_path, 0) + 1

        most_affected_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return f"""## Executive Summary

### Overall Risk Assessment
{risk_emoji} **Overall Risk Rating: {overall_risk}**
**Risk Score:** {risk_score} points

### Scan Statistics
- **Files Analyzed:** {scan_info['files_scanned']}
- **Total Vulnerabilities Found:** {total_vulns}
- **Critical Issues:** 🚨 {risk_levels['critical']}
- **High Risk Issues:** ⚠️ {risk_levels['high']}
- **Medium Risk Issues:** ⚡ {risk_levels['medium']}
- **Low Risk Issues:** ℹ️ {risk_levels['low']}

### Key Findings
{self._generate_key_findings_summary(vulnerabilities)}

### Most Vulnerable Files
{self._generate_most_affected_files(most_affected_files)}

---

"""

    def _generate_key_findings_summary(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate key findings summary"""
        if not vulnerabilities:
            return "✅ **No security vulnerabilities detected.**"

        # Count vulnerability types
        type_counts = {}
        critical_types = []

        for vuln in vulnerabilities:
            vuln_type = vuln['type'].replace('_', ' ').title()
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

            if vuln['risk_level'] == 'critical':
                critical_types.append(vuln_type)

        # Top vulnerability types
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]

        summary = []
        for vuln_type, count in top_types:
            summary.append(f"• **{vuln_type}**: {count} instances")

        if critical_types:
            unique_critical = list(set(critical_types))
            summary.insert(0, f"🚨 **Critical vulnerabilities detected**: {', '.join(unique_critical)}")

        return '\n'.join(summary)

    def _generate_most_affected_files(self, most_affected_files: List[tuple]) -> str:
        """Generate most affected files summary"""
        if not most_affected_files:
            return "No files with vulnerabilities found."

        summary = []
        for file_path, count in most_affected_files:
            # Show only relative path for brevity
            display_path = file_path.split('/')[-1] if '/' in file_path else file_path
            summary.append(f"• `{display_path}`: {count} vulnerabilities")

        return '\n'.join(summary)

    def _generate_risk_breakdown(self, scan_info: Dict[str, Any]) -> str:
        """Generate risk breakdown section"""
        risk_levels = scan_info['risk_levels']
        total = sum(risk_levels.values())

        if total == 0:
            return """## Risk Breakdown

✅ **No vulnerabilities detected across all risk levels.**

---

"""

        breakdown = """## Risk Breakdown

### Vulnerability Distribution

"""

        for level in ['critical', 'high', 'medium', 'low']:
            count = risk_levels[level]
            if count > 0:
                emoji = self.risk_level_emojis[level]
                percentage = (count / total) * 100
                breakdown += f"- {emoji} **{level.title()} Risk**: {count} vulnerabilities ({percentage:.1f}%)\n"

        breakdown += f"\n**Total vulnerabilities identified: {total}**\n\n"
        breakdown += "### Risk Level Definitions\n\n"
        breakdown += "- **🚨 Critical**: Immediate threat requiring urgent remediation (e.g., RCE, data breach)\n"
        breakdown += "- **⚠️ High**: Significant security issue that should be addressed promptly\n"
        breakdown += "- **⚡ Medium**: Security flaw that should be fixed in next release cycle\n"
        breakdown += "- **ℹ️ Low**: Minor security issue or best practice violation\n"

        return breakdown + "\n---\n\n"

    def _generate_detailed_findings(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate detailed findings section"""
        if not vulnerabilities:
            return """## Detailed Findings

✅ **No security vulnerabilities were detected during the scan.**

---

"""

        findings = """## Detailed Findings

### Vulnerability Details

"""

        # Group by risk level
        grouped_vulns = {}
        for vuln in vulnerabilities:
            risk = vuln['risk_level']
            if risk not in grouped_vulns:
                grouped_vulns[risk] = []
            grouped_vulns[risk].append(vuln)

        # Generate findings for each risk level
        for risk_level in ['critical', 'high', 'medium', 'low']:
            if risk_level in grouped_vulns:
                emoji = self.risk_level_emojis[risk_level]
                findings += f"\n#### {emoji} {risk_level.title()} Risk Vulnerabilities\n\n"

                for i, vuln in enumerate(grouped_vulns[risk_level], 1):
                    findings += self._generate_vulnerability_detail(vuln, i)

        return findings + "---\n\n"

    def _generate_vulnerability_detail(self, vuln: Dict[str, Any], index: int) -> str:
        """Generate detailed vulnerability information"""
        file_path = vuln['file_path']
        line_number = vuln['line_number']
        vuln_type = vuln['type'].replace('_', ' ').title()
        description = vuln['description']
        remediation = vuln['remediation']
        code_snippet = vuln['code_snippet']
        cwe_id = vuln.get('cwe_id', 'N/A')

        detail = f"""**{index}. {vuln_type}**
**Location:** `{file_path}:{line_number}`
**CWE ID:** {cwe_id}

**Description:** {description}

**Vulnerable Code:**
```java
{code_snippet}
```

**Remediation:** {remediation}

---

"""

        return detail

    def _generate_remediation_summary(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate remediation summary"""
        if not vulnerabilities:
            return """## Remediation Summary

✅ **No remediation actions required.**

---

"""

        summary = """## Remediation Summary

### Recommended Actions

#### Immediate Actions (Critical & High Risk)
Prioritize these fixes as they pose the highest security risk:

"""

        critical_high = [v for v in vulnerabilities if v['risk_level'] in ['critical', 'high']]

        if critical_high:
            # Group by vulnerability type for remediation
            remediation_groups = {}
            for vuln in critical_high:
                vuln_type = vuln['type']
                if vuln_type not in remediation_groups:
                    remediation_groups[vuln_type] = {
                        'count': 0,
                        'remediation': vuln['remediation'],
                        'files': set()
                    }
                remediation_groups[vuln_type]['count'] += 1
                remediation_groups[vuln_type]['files'].add(vuln['file_path'])

            for vuln_type, info in remediation_groups.items():
                type_name = vuln_type.replace('_', ' ').title()
                file_list = ', '.join([f.split('/')[-1] for f in list(info['files'])[:3]])
                if len(info['files']) > 3:
                    file_list += f" and {len(info['files']) - 3} more"

                summary += f"• **{type_name}** ({info['count']} instances): {info['remediation']}\n"
                summary += f"  - Affected files: {file_list}\n\n"
        else:
            summary += "✅ **No critical or high-risk vulnerabilities requiring immediate attention.**\n\n"

        summary += "#### Short-term Actions (Medium Risk)"
        medium_vulns = [v for v in vulnerabilities if v['risk_level'] == 'medium']
        if medium_vulns:
            summary += f"\nAddress {len(medium_vulns)} medium-risk issues in the next development cycle.\n"
        else:
            summary += "\n✅ **No medium-risk vulnerabilities identified.**\n"

        summary += "\n#### Long-term Actions (Low Risk)"
        low_vulns = [v for v in vulnerabilities if v['risk_level'] == 'low']
        if low_vulns:
            summary += f"\nAddress {len(low_vulns)} low-risk issues during regular maintenance.\n"
        else:
            summary += "\n✅ **No low-risk vulnerabilities identified.**\n"

        summary += "\n### General Recommendations\n\n"
        summary += "1. **Implement Secure Coding Standards**: Establish and enforce secure coding practices\n"
        summary += "2. **Regular Security Training**: Provide ongoing security awareness training for developers\n"
        summary += "3. **Automated Security Testing**: Integrate security scanning into CI/CD pipeline\n"
        summary += "4. **Dependency Management**: Regularly update third-party dependencies\n"
        summary += "5. **Code Reviews**: Include security review in pull request process\n"

        return summary + "\n---\n\n"

    def _generate_compliance_assessment(self, scan_info: Dict[str, Any]) -> str:
        """Generate compliance assessment"""
        risk_levels = scan_info['risk_levels']
        total_vulns = sum(risk_levels.values())

        compliance = """## Compliance Assessment

### Security Standards Compliance

Based on the Java Security Coding Standards, this project demonstrates:

"""

        if total_vulns == 0:
            compliance += "✅ **Excellent Compliance**: No security violations detected\n"
        elif risk_levels['critical'] == 0 and risk_levels['high'] == 0:
            compliance += "✅ **Good Compliance**: No critical or high-risk violations\n"
        elif risk_levels['critical'] == 0:
            compliance += "⚠️ **Moderate Compliance**: Some high-risk issues require attention\n"
        else:
            compliance += "🚨 **Poor Compliance**: Critical security violations require immediate action\n"

        compliance += "\n### Security Posture Assessment\n\n"
        compliance += f"- **Overall Security Score**: {max(0, 100 - (risk_levels['critical'] * 20 + risk_levels['high'] * 10 + risk_levels['medium'] * 5 + risk_levels['low'] * 2))}/100\n"
        compliance += f"- **Files with Vulnerabilities**: {scan_info['files_scanned'] if total_vulns > 0 else 0}/{scan_info['files_scanned']}\n"
        compliance += f"- **Security Density**: {(total_vulns / max(1, scan_info['files_scanned'])):.1f} vulnerabilities per file\n"

        return compliance + "\n---\n\n"

    def _generate_appendix(self) -> str:
        """Generate appendix section"""
        return """## Appendix

### About This Report

This security assessment was performed using the Java Security Vulnerability Scanner, which analyzes Java source code for security vulnerabilities based on:

- OWASP Top 10 Web Application Security Risks
- CWE (Common Weakness Enumeration) standards
- Industry best practices for secure Java development
- Enterprise security coding standards

### Vulnerability Categories Analyzed

1. **SQL Injection** (CWE-89) - Injection of malicious SQL code
2. **Path Traversal** (CWE-22) - Directory traversal attacks
3. **Cross-Site Scripting (XSS)** (CWE-79) - Injection of malicious scripts
4. **Command Injection** (CWE-78) - Execution of system commands
5. **XXE (XML External Entity)** (CWE-611) - XML parsing vulnerabilities
6. **Unsafe Deserialization** (CWE-502) - Deserialization attacks
7. **Arbitrary File Upload** (CWE-434) - File upload vulnerabilities
8. **Server-Side Request Forgery (SSRF)** (CWE-918) - Server-side request attacks
9. **Information Disclosure** (CWE-200) - Exposure of sensitive information
10. **Weak Cryptography** (CWE-327) - Use of weak encryption algorithms

### Next Steps

1. Review and prioritize identified vulnerabilities
2. Implement recommended remediation actions
3. Conduct follow-up security assessment
4. Establish ongoing security monitoring
5. Integrate security scanning into development lifecycle

---

*Report generated by Java Security Vulnerability Scanner*
*For questions about this report, consult your security team or security documentation*
"""

    def _format_datetime(self, iso_datetime: str) -> str:
        """Format ISO datetime for human reading"""
        try:
            dt = datetime.fromisoformat(iso_datetime.replace('Z', '+00:00'))
            return dt.strftime('%B %d, %Y at %I:%M %p UTC')
        except:
            return iso_datetime