---
name: ai-java-security-scanner
description: AI-enhanced Java code security vulnerability scanner using Claude's semantic analysis capabilities. Use when users need intelligent security analysis that goes beyond pattern matching. Leverages Claude's AI to understand code semantics, business logic, and context to identify complex security vulnerabilities including zero-day patterns. Provides intelligent remediation suggestions and reduces false positives through semantic understanding. Analyzes 13+ vulnerability types with deep code comprehension.
---

# AI-Enhanced Java Security Scanner

## Overview

This skill provides **AI-enhanced** security vulnerability scanning that goes beyond traditional pattern matching. It leverages Claude's semantic understanding to analyze code logic, business context, and complex relationships between components. The AI can identify sophisticated vulnerabilities, zero-day patterns, and contextual security issues that traditional scanners miss.

## Quick Start

To perform an AI-enhanced security vulnerability scan on a Java project:

```bash
# AI-powered scan with semantic analysis
python3 scripts/ai_vulnerability_scanner.py .

# Scan specific project directory with AI
python3 scripts/ai_vulnerability_scanner.py /path/to/java/project

# Generate AI analysis report
python3 scripts/ai_vulnerability_scanner.py /path/to/project --output ai_security_report.md

# Set AI confidence threshold
python3 scripts/ai_vulnerability_scanner.py /path/to/project --confidence 0.8
```

## Supported Vulnerability Types

The AI scanner goes beyond traditional pattern matching to identify sophisticated security issues:

### AI-Enhanced Detection Capabilities

**Beyond Pattern Matching:**
- **Semantic Code Analysis**: Understands code intent, business logic, and data flow
- **Contextual Risk Assessment**: Evaluates vulnerabilities in business context
- **Zero-Day Pattern Discovery**: Identifies previously unknown vulnerability patterns
- **False Positive Reduction**: Uses semantic understanding to minimize incorrect findings

**Traditional Detection (Enhanced with AI):**
The AI-enhanced scanner identifies the following vulnerability categories:

### Critical Risk Vulnerabilities
- **SQL Injection** - Malicious SQL code execution through unsanitized input
- **Command Injection** - System command execution through user input
- **XXE (XML External Entity)** - XML parsing vulnerabilities
- **Java Deserialization** - Unsafe object deserialization attacks

### High Risk Vulnerabilities
- **Path Traversal** - Directory traversal attacks (../../../etc/passwd)
- **File Upload** - Arbitrary file upload vulnerabilities
- **SSRF** - Server-Side Request Forgery
- **XSS** - Cross-Site Scripting (reflected, stored, DOM-based)

### Medium Risk Vulnerabilities
- **URL Redirection** - Open redirect vulnerabilities
- **SpEL Injection** - Spring Expression Language injection
- **Information Disclosure** - Sensitive information exposure
- **Authentication/Authorization** - Access control bypasses
- **Cryptographic Issues** - Weak encryption and random number generation
- **Memory Leaks** - ThreadLocal and other resource leaks

## Scanner Workflow

### Step 1: Project Discovery
- Recursively scan all directories from the specified path
- Identify all `.java` files for analysis
- Build project structure map for context analysis

### Step 2: Code Analysis
For each Java file, perform semantic analysis using:
- **Pattern Matching** - Known vulnerability signatures
- **Data Flow Analysis** - Input validation and sanitization tracking
- **Contextual Analysis** - Framework-specific security patterns
- **Library/Dependency Analysis** - Third-party component vulnerabilities

### Step 3: Vulnerability Detection
Apply detection rules from [references/vulnerability_patterns.md](references/vulnerability_patterns.md):
- Identify risky code patterns
- Validate input validation mechanisms
- Check for security framework usage
- Analyze authentication/authorization logic

### Step 4: Risk Assessment
Classify findings using [references/detection_rules.md](references/detection_rules.md):
- **Critical** - Remote code execution, data breach
- **High** - Privilege escalation, data manipulation
- **Medium** - Information disclosure, denial of service
- **Low** - Configuration issues, minor security flaws

### Step 5: Report Generation
Generate comprehensive security audit report using [assets/report_template.md](assets/report_template.md):
- Executive summary with risk statistics
- Detailed vulnerability findings
- Code snippets with highlighted issues
- Remediation recommendations
- Compliance assessment

## Usage Examples

**Example 1: AI-Powered Project Scan**
```
User: "用AI分析一下这个项目的代码漏洞"
Claude: 使用ai_vulnerability_scanner.py进行深度语义分析，发现传统扫描器可能遗漏的复杂漏洞
```

**Example 2: Intelligent Vulnerability Analysis**
```
User: "帮我用AI深入分析src/main/java目录下的安全问题"
Claude: 使用AI语义分析，理解代码业务逻辑，识别上下文相关的安全风险
```

**Example 3: Zero-Day Pattern Discovery**
```
User: "这个项目有没有未知的漏洞模式？"
Claude: 使用AI进行模式识别和分析，发现可能的新型攻击向量和逻辑缺陷
```

**Example 4: Smart Remediation**
```
User: "基于AI分析结果给出智能修复建议"
Claude: AI分析代码上下文，提供个性化的、业务相关的安全修复方案
```

## Resources

### scripts/
AI-enhanced security analysis tools:

- **`ai_vulnerability_scanner.py`** - AI-powered main scanner that leverages Claude's semantic analysis
- **`code_analyzer.py`** - Traditional pattern-based analyzer (supplemented by AI analysis)
- **`report_generator.py`** - Enhanced report generator with AI insights and recommendations

### references/
Security standards and detection methodology:

- **`java_security_standards.md`** - Complete enterprise Java security coding standards (13 vulnerability categories)
- **`vulnerability_patterns.md`** - Detailed vulnerability signatures, code patterns, and detection rules
- **`detection_rules.md`** - Risk assessment framework and remediation guidelines

### assets/
Report generation and analysis templates:

- **`report_template.md`** - Structured template for security audit reports with executive summary sections

## Integration Notes

This skill works with standard Java project structures:
- Maven projects (src/main/java, src/test/java)
- Gradle projects (src/main/java, src/test/java)
- Custom Java project layouts
- Spring Boot, Spring MVC, and other Java frameworks

The scanner analyzes code semantics, not just text patterns, enabling detection of complex vulnerabilities that require understanding of data flow, context, and framework-specific security mechanisms.
