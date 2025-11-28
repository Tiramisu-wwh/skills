# Java Security Vulnerability Detection Rules

This document defines the detection rules, risk assessment framework, and remediation guidelines used by the Java Security Vulnerability Scanner.

## Risk Assessment Framework

### Risk Level Classification

| Risk Level | Score Range | Definition | Response Time |
|------------|-------------|------------|---------------|
| **Critical** | 8-10 points | Immediate threat to system security; potential for data breach or system compromise | 24-48 hours |
| **High** | 5-7 points | Significant security issue that could lead to privilege escalation or data manipulation | 1-2 weeks |
| **Medium** | 2-4 points | Security flaw that should be addressed in the next development cycle | 1 month |
| **Low** | 0-1 points | Minor security issue or best practice violation | Next major release |

### Base Risk Scores

Each vulnerability category has a base risk score:

| Vulnerability Type | Base Score | Rationale |
|--------------------|------------|-----------|
| SQL Injection | 10 | Direct database access, potential data exfiltration |
| Command Injection | 10 | System compromise possible |
| Unsafe Deserialization | 10 | Remote code execution potential |
| XXE | 9 | Information disclosure, potential file access |
| Path Traversal | 8 | Arbitrary file system access |
| File Upload | 8 | Arbitrary code execution possible |
| SSRF | 7 | Internal network access |
| XSS | 7 | Client-side script execution, session theft |
| URL Redirection | 5 | Phishing attacks possible |
| SpEL Injection | 5 | Code execution in Spring applications |
| Information Disclosure | 4 | Sensitive data exposure |
| Weak Cryptography | 4 | Compromised data confidentiality |
| Authentication/Authorization | 6 | Access control bypass |
| Memory Leaks | 2 | Denial of service potential |

## Context Analysis Rules

### Context Boosters (Risk Amplifiers)

These factors increase the vulnerability risk score:

| Context Factor | Score Bonus | Detection Patterns |
|----------------|-------------|-------------------|
| **User Input** | +2 | `request.getParameter()`, `request.getQueryString()`, user-provided data |
| **Network Input** | +3 | HTTP requests, web services, external API calls |
| **File Operations** | +2 | `File`, `FileInputStream`, `FileOutputStream`, file path manipulation |
| **Database Operations** | +3 | SQL queries, database connections, data persistence |
| **Command Execution** | +4 | `Runtime.exec()`, `ProcessBuilder`, system calls |
| **Web Response Output** | +2 | `response.getWriter()`, JSP output, template rendering |
| **Administrative Functions** | +3 | Admin endpoints, configuration changes, user management |
| **Financial Operations** | +4 | Payment processing, financial calculations, transactions |
| **Personal Data Processing** | +3 | PII handling, user profiles, authentication data |

### Mitigation Indicators (Risk Reducers)

These factors decrease the vulnerability risk score:

| Mitigation Factor | Score Reduction | Detection Patterns |
|-------------------|-----------------|-------------------|
| **Parameterized Queries** | -3 | `PreparedStatement`, `?` placeholders, parameter binding |
| **Input Validation** | -2 | Validation methods, whitelist checking, regex validation |
| **Output Escaping** | -2 | `StringEscapeUtils`, HTML encoding, URL encoding |
| **Whelist Validation** | -3 | Enum validation, allowed values list |
| **Sanitization** | -2 | Input cleaning, XSS filtering, SQL injection filtering |
| **Authentication Required** | -2 | `@PreAuthorize`, authentication checks, login required |
| **Authorization Checks** | -2 | Role-based access control, permission checks |
| **Secure Framework Usage** | -2 | Spring Security, OWASP ESAPI, secure libraries |
| **HTTPS Enforcement** | -1 | SSL/TLS configuration, secure headers |
| **Security Headers** | -1 | CSP, HSTS, XSS protection headers |

## Detection Patterns

### SQL Injection Detection

**Primary Patterns**:
```regex
# Direct SQL concatenation
executeQuery\s*\(\s*["\'].*\+.*["\']
execute\s*\(\s*["\'].*\+.*["\']
createStatement\s*\(\s*\)

# String concatenation in SQL
String\s+\w+\s*=\s*["\'].*\+.*["\'];.*execute
```

**Context Indicators**:
- `request.getParameter()`, `request.getQueryString()`
- Direct string concatenation with SQL keywords
- Missing parameterization

**Mitigation Indicators**:
- `PreparedStatement` usage
- Parameter binding with `?` or named parameters
- ORM framework usage (JPA, Hibernate, MyBatis)
- Input validation before SQL construction

### Command Injection Detection

**Primary Patterns**:
```regex
Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(\s*["\'].*\+.*
ProcessBuilder\s*\([^)]*\+.*
exec\s*\(\s*["\'].*\+.*
```

**Context Indicators**:
- User input in command strings
- Shell metacharacters (`;`, `&`, `|`, `>`, `<`)
- File paths from untrusted sources

**Mitigation Indicators**:
- Input validation with whitelisting
- Command argument arrays instead of string concatenation
- Restricted command execution environments
- Proper escaping and sanitization

### XSS Detection

**Primary Patterns**:
```regex
request\.getParameter\s*\([^)]+\)
request\.getQueryString\s*\(\s*\)
out\.print\s*\([^)]*\+
response\.getWriter\s*\(\s*\)\.print
```

**Context Indicators**:
- Output without encoding
- Template engines without auto-escaping
- Direct HTML manipulation

**Mitigation Indicators**:
- Output encoding functions
- Auto-escaping template engines
- Content Security Policy headers
- Input validation and sanitization

## Data Flow Analysis

### Source-Sink Analysis

The scanner tracks data flow from sources (user input) to sinks (dangerous operations):

**Sources**:
- HTTP parameters: `request.getParameter()`
- HTTP headers: `request.getHeader()`
- Query strings: `request.getQueryString()`
- File uploads: `MultipartFile`
- Database results: `ResultSet`
- Web service responses

**Sinks**:
- SQL execution: `executeQuery()`, `execute()`
- Command execution: `Runtime.exec()`, `ProcessBuilder`
- File operations: `File`, `FileInputStream`
- HTML output: `out.print()`, template rendering
- Redirects: `sendRedirect()`

### Taint Propagation Rules

Data is considered tainted when:
1. Originates from untrusted sources
2. Flows through variables without sanitization
3. Reaches sensitive operations

Sanitization breaks taint propagation when:
- Input validation with whitelisting
- Output encoding/escaping
- Parameterized queries
- Type conversion and validation

## Framework-Specific Rules

### Spring Framework

**Spring Security Patterns**:
- `@PreAuthorize` annotations: -2 risk points
- `@Secured` annotations: -2 risk points
- `SecurityContextHolder`: -1 risk point

**Spring MVC Patterns**:
- `@RequestParam` with validation: -1 risk point
- `@PathVariable` with validation: -1 risk point
- Form backing objects with validation: -1 risk point

**Spring Data JPA**:
- `@Query` with parameters: -2 risk points
- Repository methods: -1 risk point
- Entity validation: -1 risk point

### JSP/Servlets

**Secure Patterns**:
- JSTL `<c:out>` tag: -1 risk point
- Expression language with escaping: -1 risk point
- Filter-based security: -2 risk points

### Apache Struts

**Secure Patterns**:
- Struts validation framework: -1 risk point
- OGNL type conversion: -1 risk point
- Interceptor-based security: -2 risk points

## Configuration Analysis

### Security Configuration Files

The scanner analyzes:
- `web.xml` for security constraints
- Spring Security configuration files
- Application properties files
- Descriptor files (`web.xml`, `application.xml`)

**Secure Configuration Indicators**:
```xml
<!-- web.xml security constraints -->
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Secure Area</web-resource-name>
        <url-pattern>/secure/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

### Dependency Analysis

**Vulnerable Dependencies Check**:
- Outdated libraries with known CVEs
- Dependencies with known vulnerabilities
- Missing security patches

## Remediation Prioritization

### Immediate Action (Critical)
1. Remote code execution vulnerabilities
2. SQL injection in authentication/authorization
3. Command injection with user input
4. Deserialization of untrusted data

### Short-term Action (High)
1. XSS in critical functionality
2. Path traversal with sensitive files
3. File upload vulnerabilities
4. Authentication bypass issues

### Medium-term Action (Medium)
1. Information disclosure
2. Weak cryptography usage
3. Missing security headers
4. Insecure direct object references

### Long-term Action (Low)
1. Logging security issues
2. Configuration improvements
3. Code quality issues
4. Best practice violations

## Reporting Guidelines

### Vulnerability Classification

Each vulnerability report includes:
- **CWE ID**: Standard weakness enumeration
- **CVSS Score**: Common Vulnerability Scoring System (when applicable)
- **OWASP Category**: OWASP Top 10 mapping
- **Compliance Impact**: Regulatory compliance implications

### Remediation Recommendations

For each vulnerability type:
- **Immediate Fix**: Code change example
- **Long-term Prevention**: Process improvements
- **Testing Guidance**: How to verify the fix
- **Monitoring**: How to detect similar issues

### Executive Summary

High-level metrics for management:
- Overall risk rating
- Compliance status
- Business impact assessment
- Remediation timeline recommendations

## Integration with Development Processes

### CI/CD Integration

**Automated Gates**:
- Block deployment on critical vulnerabilities
- Warn on high vulnerabilities
- Report on medium/low vulnerabilities

**Quality Gates**:
- Maximum allowed critical vulnerabilities: 0
- Maximum allowed high vulnerabilities: 5
- Security score threshold: 8.0/10

### Code Review Integration

**Security Review Checklist**:
- [ ] Input validation implemented
- [ ] Output encoding used
- [ ] Parameterized queries
- [ ] Authentication/authorization checks
- [ ] Error handling doesn't leak information

## Customization and Extension

### Adding Custom Rules

Organizations can extend the scanner by:

1. **Pattern Files**: Add new vulnerability patterns
2. **Context Rules**: Define organization-specific context factors
3. **Risk Weights**: Adjust risk scores based on organizational priorities
4. **Compliance Mappings**: Map to industry standards (PCI DSS, HIPAA, SOX)

### Integration with Security Tools

- **Static Analysis Security Testing (SAST)** tools
- **Software Composition Analysis (SCA)** tools
- **Dynamic Application Security Testing (DAST)** tools
- **Interactive Application Security Testing (IAST)** tools

## References and Standards

- **OWASP Application Security Verification Standard (ASVS)**
- **NIST Secure Coding Standards**
- **SANS Top 25 Most Dangerous Software Errors**
- **Common Weakness Enumeration (CWE)**
- **Common Vulnerability Scoring System (CVSS)**