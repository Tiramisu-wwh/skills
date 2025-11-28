#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Code Analyzer Module
Performs semantic analysis of Java code to detect security vulnerabilities
"""

import os
import re
import ast
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class Vulnerability:
    """Represents a security vulnerability finding"""
    file_path: str
    line_number: int
    vulnerability_type: str
    risk_level: str
    description: str
    code_snippet: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

class CodeAnalyzer:
    """Java code security analyzer"""

    def __init__(self):
        # Load vulnerability patterns from references
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.detection_rules = self._load_detection_rules()

    def _load_vulnerability_patterns(self) -> Dict[str, Dict]:
        """Load vulnerability patterns and signatures"""
        # These patterns would normally be loaded from references/vulnerability_patterns.md
        # For now, include essential patterns inline

        return {
            'sql_injection': {
                'patterns': [
                    r'executeQuery\s*\(\s*["\'].*\+.*["\']',
                    r'execute\s*\(\s*["\'].*\+.*["\']',
                    r'createStatement\s*\(\s*\)',
                    r'prepareStatement\s*\(\s*["\'].*\+.*["\']',
                    r'String\s+\w+\s*=\s*["\'].*\+.*["\'];.*execute',
                ],
                'safe_keywords': ['PreparedStatement', 'CallableStatement', 'setParameter', '?'],
                'risk_level': 'critical',
                'description': 'Potential SQL injection vulnerability',
                'remediation': 'Use parameterized queries (PreparedStatement) instead of string concatenation',
                'cwe_id': 'CWE-89'
            },
            'path_traversal': {
                'patterns': [
                    r'new\s+File\s*\(\s*["\'].*\+.*["\']',
                    r'FileInputStream\s*\(\s*["\'].*\+.*["\']',
                    r'FileOutputStream\s*\(\s*["\'].*\+.*["\']',
                    r'Files\.read\s*\(\s*Paths\.get\s*\(\s*["\'].*\+',
                    r'getCanonicalPath\s*\(\s*\).*\+',
                    r'getAbsolutePath\s*\(\s*\).*\+',
                ],
                'dangerous_sequences': ['../', '..\\', '/etc/', '/proc/', 'C:\\\\'],
                'risk_level': 'high',
                'description': 'Potential path traversal vulnerability',
                'remediation': 'Validate and sanitize file paths, use whitelist of allowed directories',
                'cwe_id': 'CWE-22'
            },
            'xss': {
                'patterns': [
                    r'request\.getParameter\s*\([^)]+\)',
                    r'request\.getQueryString\s*\(\s*\)',
                    r'request\.getHeader\s*\([^)]+\)',
                    r'out\.print\s*\([^)]*\+',
                    r'out\.write\s*\([^)]*\+',
                    r'response\.getWriter\s*\(\s*\)\.print',
                ],
                'context_checks': ['innerHTML', 'document.write', 'eval'],
                'risk_level': 'high',
                'description': 'Potential Cross-Site Scripting (XSS) vulnerability',
                'remediation': 'Validate input, escape output, use CSP headers',
                'cwe_id': 'CWE-79'
            },
            'command_injection': {
                'patterns': [
                    r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(\s*["\'].*\+',
                    r'ProcessBuilder\s*\([^)]*\+',
                    r'exec\s*\(\s*["\'].*\+',
                    r'system\s*\(\s*["\'].*\+',
                    r'popen\s*\(\s*["\'].*\+',
                ],
                'dangerous_commands': ['rm', 'del', 'cat', 'type', 'dir', 'ls'],
                'risk_level': 'critical',
                'description': 'Potential command injection vulnerability',
                'remediation': 'Avoid system calls with user input, use whitelist validation',
                'cwe_id': 'CWE-78'
            },
            'xxe': {
                'patterns': [
                    r'DocumentBuilderFactory\.newInstance\s*\(\s*\)',
                    r'SAXParserFactory\.newInstance\s*\(\s*\)',
                    r'XMLReaderFactory\.createXMLReader\s*\(\s*\)',
                    r'new\s+FileInputStream\s*\([^)]*\.xml',
                    r'parse\s*\([^)]*\.xml',
                ],
                'risky_configs': ['setFeature', 'setNamespaceAware', 'setValidating'],
                'risk_level': 'high',
                'description': 'Potential XXE (XML External Entity) vulnerability',
                'remediation': 'Disable external entities in XML parsers, validate XML input',
                'cwe_id': 'CWE-611'
            },
            'deserialization': {
                'patterns': [
                    r'ObjectInputStream\s*\([^)]+\)',
                    r'readObject\s*\(\s*\)',
                    r'XMLDecoder\s*\([^)]+\)',
                    r'Yaml\s*\([^)]+load',
                    r'Gson\s*\([^)]+fromJson',
                    r'Jackson.*readValue',
                ],
                'dangerous_classes': ['ObjectInputStream', 'XMLDecoder', 'Yaml', 'Gson', 'ObjectMapper'],
                'risk_level': 'critical',
                'description': 'Potential unsafe deserialization vulnerability',
                'remediation': 'Validate serialized data, use safe deserialization practices',
                'cwe_id': 'CWE-502'
            },
            'file_upload': {
                'patterns': [
                    r'File\s+[^;]*upload',
                    r'MultipartFile\s+\w+',
                    r' CommonsFileUploadSupport',
                    r'setContentType\s*\([^)]*\)',
                    r'getInputStream\s*\(\s*\)',
                ],
                'dangerous_extensions': ['.exe', '.bat', '.cmd', '.sh', '.php', '.jsp', '.asp'],
                'risk_level': 'high',
                'description': 'Potential arbitrary file upload vulnerability',
                'remediation': 'Validate file types, scan uploaded files, use secure storage',
                'cwe_id': 'CWE-434'
            },
            'ssrf': {
                'patterns': [
                    r'URLConnection\s*\([^)]*\+',
                    r'HttpClient\s*\([^)]*\+',
                    r'RestTemplate\s*\([^)]*\+',
                    r'OkHttpClient\s*\([^)]*\+',
                    r'openConnection\s*\([^)]*\+',
                ],
                'dangerous_protocols': ['file://', 'ftp://', 'gopher://', 'dict://'],
                'risk_level': 'high',
                'description': 'Potential Server-Side Request Forgery (SSRF) vulnerability',
                'remediation': 'Validate and whitelist URLs, restrict network access',
                'cwe_id': 'CWE-918'
            },
            'information_disclosure': {
                'patterns': [
                    r'System\.out\.print',
                    r'System\.err\.print',
                    r'printStackTrace\s*\(\s*\)',
                    r'e\.getMessage\s*\(\s*\).*out',
                    r'logger\.error.*exception',
                ],
                'sensitive_data': ['password', 'token', 'secret', 'key', 'credential'],
                'risk_level': 'medium',
                'description': 'Potential information disclosure vulnerability',
                'remediation': 'Avoid logging sensitive information, implement proper error handling',
                'cwe_id': 'CWE-200'
            },
            'weak_crypto': {
                'patterns': [
                    r'MD5\s*\(\s*\)',
                    r'SHA1\s*\(\s*\)',
                    r'DES\s*\(\s*\)',
                    r'RC4\s*\(\s*\)',
                    r'random\s*\(\s*\)',
                    r'Math\.random\s*\(\s*\)',
                ],
                'weak_algorithms': ['MD5', 'SHA1', 'DES', 'RC4', 'random()', 'Math.random'],
                'risk_level': 'medium',
                'description': 'Weak cryptographic algorithm or random number generation',
                'remediation': 'Use strong algorithms (SHA-256+, AES) and secure random generators',
                'cwe_id': 'CWE-327'
            }
        }

    def _load_detection_rules(self) -> Dict[str, Dict]:
        """Load risk assessment and detection rules"""
        return {
            'risk_weights': {
                'critical': 10,
                'high': 7,
                'medium': 4,
                'low': 1
            },
            'context_boosters': {
                'user_input': 2,
                'network_input': 3,
                'file_operation': 2,
                'database_operation': 3,
                'command_execution': 4,
                'web_response': 2
            },
            'mitigation_indicators': {
                'parameterized': -3,
                'validation': -2,
                'escaping': -2,
                'whitelist': -3,
                'sanitization': -2,
                'authentication': -2,
                'authorization': -2
            }
        }

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze a single Java file for vulnerabilities"""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return vulnerabilities

        lines = content.split('\n')

        # Check each vulnerability type
        for vuln_type, patterns in self.vulnerability_patterns.items():
            file_vulnerabilities = self._check_vulnerability_type(
                file_path, lines, content, vuln_type, patterns
            )
            vulnerabilities.extend(file_vulnerabilities)

        return vulnerabilities

    def _check_vulnerability_type(self, file_path: str, lines: List[str],
                                content: str, vuln_type: str, patterns: Dict) -> List[Dict[str, Any]]:
        """Check for specific vulnerability type"""
        vulnerabilities = []

        for line_num, line in enumerate(lines, 1):
            line_vulnerabilities = self._analyze_line_for_vulnerability(
                file_path, line_num, line.strip(), content, vuln_type, patterns
            )
            vulnerabilities.extend(line_vulnerabilities)

        return vulnerabilities

    def _analyze_line_for_vulnerability(self, file_path: str, line_num: int, line: str,
                                      content: str, vuln_type: str, patterns: Dict) -> List[Dict[str, Any]]:
        """Analyze a specific line for vulnerability patterns"""
        vulnerabilities = []

        # Check against vulnerability patterns
        for pattern in patterns['patterns']:
            if re.search(pattern, line, re.IGNORECASE):
                # Additional context analysis
                context_score = self._analyze_context(line, content, line_num)

                # Check for mitigation indicators
                mitigation_score = self._check_mitigation_indicators(line, content, line_num)

                # Calculate final risk level
                final_risk = self._calculate_risk_level(
                    patterns['risk_level'], context_score, mitigation_score
                )

                # Get code snippet (show context)
                code_snippet = self._get_code_snippet(content, line_num)

                vulnerability = {
                    'file_path': file_path,
                    'line_number': line_num,
                    'type': vuln_type,
                    'risk_level': final_risk,
                    'description': patterns['description'],
                    'code_snippet': code_snippet,
                    'remediation': patterns['remediation'],
                    'cwe_id': patterns.get('cwe_id'),
                    'pattern_matched': pattern,
                    'context_score': context_score,
                    'mitigation_score': mitigation_score
                }

                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _analyze_context(self, line: str, content: str, line_num: int) -> float:
        """Analyze context to determine vulnerability severity"""
        context_score = 0

        # Check for user input sources
        if any(source in line.lower() for source in ['request.', 'param', 'input', 'user']):
            context_score += self.detection_rules['context_boosters']['user_input']

        # Check for network input
        if any(source in line.lower() for source in ['url', 'http', 'socket']):
            context_score += self.detection_rules['context_boosters']['network_input']

        # Check for file operations
        if any(op in line.lower() for op in ['file', 'path', 'stream']):
            context_score += self.detection_rules['context_boosters']['file_operation']

        # Check for database operations
        if any(op in line.lower() for op in ['sql', 'query', 'execute', 'database']):
            context_score += self.detection_rules['context_boosters']['database_operation']

        # Check for command execution
        if any(op in line.lower() for op in ['runtime', 'process', 'exec', 'system']):
            context_score += self.detection_rules['context_boosters']['command_execution']

        # Check for web response
        if any(op in line.lower() for op in ['response', 'out.print', 'write']):
            context_score += self.detection_rules['context_boosters']['web_response']

        return context_score

    def _check_mitigation_indicators(self, line: str, content: str, line_num: int) -> float:
        """Check for security mitigation indicators"""
        mitigation_score = 0

        # Look in current line and surrounding lines
        lines_to_check = 5  # Check 2 lines before and after
        start_line = max(0, line_num - 1 - lines_to_check // 2)
        end_line = min(len(content.split('\n')), line_num - 1 + lines_to_check // 2 + 1)

        surrounding_lines = content.split('\n')[start_line:end_line]
        surrounding_text = ' '.join(surrounding_lines).lower()

        # Check for mitigation patterns
        for indicator, score in self.detection_rules['mitigation_indicators'].items():
            if indicator in surrounding_text:
                mitigation_score += score

        return mitigation_score

    def _calculate_risk_level(self, base_risk: str, context_score: float,
                            mitigation_score: float) -> str:
        """Calculate final risk level based on context and mitigation"""
        base_weight = self.detection_rules['risk_weights'][base_risk.lower()]
        final_score = base_weight + context_score + mitigation_score

        # Map score back to risk level
        if final_score >= 8:
            return 'critical'
        elif final_score >= 5:
            return 'high'
        elif final_score >= 2:
            return 'medium'
        else:
            return 'low'

    def _get_code_snippet(self, content: str, line_num: int, context_lines: int = 3) -> str:
        """Extract code snippet around the vulnerability"""
        lines = content.split('\n')
        start = max(0, line_num - 1 - context_lines)
        end = min(len(lines), line_num + context_lines)

        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i+1:4d}: {lines[i]}")

        return '\n'.join(snippet_lines)