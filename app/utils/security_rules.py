# app/utils/security_rules.py

"""Rule-Based Security Checker

Pattern-based security scanning for common vulnerabilities
including SQL injection, XSS, secrets, command injection, etc.
"""

from typing import List, Dict, Any
import re
import logging

from app.models.analysis import SecurityIssue, Severity

logger = logging.getLogger(__name__)


class SecurityChecker:
    """Rule-based security vulnerability scanner"""
    
    # Security vulnerability patterns with severity and recommendations
    SECURITY_PATTERNS = {
        'sql_injection': {
            'patterns': [
                r'execute\s*\(\s*.*\+.*\)',  # SQL string concatenation
                r'query\s*=\s*.*\+.*',  # Query variable with concatenation
                r'f["\']SELECT.*\{.*\}',  # f-strings in SQL
                r'f"SELECT.*\{',  # f-strings in SQL (double quotes)
                r"f'SELECT.*\{",  # f-strings in SQL (single quotes)
            ],
            'severity': Severity.CRITICAL,
            'title': 'Potential SQL Injection Vulnerability',
            'recommendation': 'Use parameterized queries, prepared statements, or ORM methods instead of string concatenation.',
            'cwe_id': 'CWE-89'
        },
        'hardcoded_secrets': {
            'patterns': [
                r'sk_live_[A-Za-z0-9]{16,}',  # Stripe-like keys
                r'AKIA[A-Z0-9]{16}',  # AWS access keys
                r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][A-Za-z0-9+/=_-]{16,}["\']',
                r'(?i)(password|passwd)\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'postgresql://[^:]+:[^@]+@',  # Database URLs with passwords
            ],
            'severity': Severity.CRITICAL,
            'title': 'Hardcoded Secret Detected',
            'recommendation': 'Use environment variables, secret managers (AWS Secrets Manager, Azure Key Vault), or config files excluded from version control.',
            'cwe_id': 'CWE-798'
        },
        'unsafe_deserialization': {
            'patterns': [
                r'pickle\.loads?\s*\(',  # Python pickle
                r'yaml\.load\s*\([^)]*\)',  # PyYAML unsafe load
            ],
            'severity': Severity.CRITICAL,
            'title': 'Unsafe Deserialization',
            'recommendation': 'Use yaml.safe_load() instead of yaml.load(), avoid pickle with untrusted data.',
            'cwe_id': 'CWE-502'
        },
        'command_injection': {
            'patterns': [
                r'os\.system\s*\(',  # os.system
                r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',  # subprocess with shell=True
                r'\beval\s*\(',  # eval() function
                r'\bexec\s*\(',  # exec() function
                r'open\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,\)]',  # open() with variable
            ],
            'severity': Severity.CRITICAL,
            'title': 'Potential Command Injection / Code Execution',
            'recommendation': 'Avoid shell=True in subprocess, use list arguments, validate and sanitize all user inputs. Never use eval()/exec() with user input.',
            'cwe_id': 'CWE-78'
        },
        'xss_vulnerability': {
            'patterns': [
                r'dangerouslySetInnerHTML',  # React XSS
                r'innerHTML\s*=',  # DOM XSS
                r'outerHTML\s*=',
                r'document\.write\s*\(',
                r'\.html\s*\([^)]*\+',  # jQuery .html() with concatenation
            ],
            'severity': Severity.HIGH,
            'title': 'Potential Cross-Site Scripting (XSS)',
            'recommendation': 'Sanitize user input, use textContent instead of innerHTML, escape HTML entities, use CSP headers.',
            'cwe_id': 'CWE-79'
        },
        'path_traversal': {
            'patterns': [
                r'open\s*\(\s*filename',  # open(filename) - user-controlled path
                r'open\s*\(\s*file_path',  # open(file_path)
                r'open\s*\(\s*path\s*[,\)]',  # open(path)
                r'os\.path\.join\s*\([^)]*filename',  # os.path.join with filename param
            ],
            'severity': Severity.HIGH,
            'title': 'Potential Path Traversal',
            'recommendation': 'Validate file paths, use os.path.abspath() and check if result is within allowed directory, avoid user-controlled paths.',
            'cwe_id': 'CWE-22'
        },
        'weak_crypto': {
            'patterns': [
                r'hashlib\.md5\s*\(',  # Weak hash MD5
                r'hashlib\.sha1\s*\(',  # Weak hash SHA1
                r'\.md5\s*\(',  # MD5 method call
                r'\.sha1\s*\(',  # SHA1 method call
            ],
            'severity': Severity.HIGH,
            'title': 'Weak Cryptographic Algorithm',
            'recommendation': 'Use SHA-256 or better for hashing, AES for encryption, secrets module or os.urandom() for random values.',
            'cwe_id': 'CWE-327'
        },
        'insecure_random': {
            'patterns': [
                r'\brandom\.random\s*\(',  # Not cryptographically secure
                r'\brandom\.randint\s*\(',
                r'Math\.random\s*\(',  # JavaScript
            ],
            'severity': Severity.MEDIUM,
            'title': 'Insecure Random Number Generation',
            'recommendation': 'Use secrets module (Python) or crypto.getRandomValues() (JavaScript) for security-sensitive operations.',
            'cwe_id': 'CWE-330'
        },
        'missing_auth_check': {
            'patterns': [
                r"@app\.route\s*\(\s*['\"].*admin",  # Flask admin route
                r"@app\.route\s*\([^)]*methods\s*=\s*\[['\"]DELETE",  # DELETE without auth
            ],
            'severity': Severity.HIGH,
            'title': 'Potential Missing Authentication Check',
            'recommendation': 'Add authentication decorators (@login_required, Depends(get_current_user)) to protected endpoints.',
            'cwe_id': 'CWE-306'
        },
        'debug_mode': {
            'patterns': [
                r"['\"]\s*DEBUG\s*['\"]?\s*\]\s*=\s*True",  # config['DEBUG'] = True
                r"\.config\s*\[['\"]DEBUG['\"]]\s*=\s*True",  # app.config['DEBUG'] = True
                r'app\.run\s*\([^)]*debug\s*=\s*True',
                r'app\.debug\s*=\s*True',
            ],
            'severity': Severity.MEDIUM,
            'title': 'Debug Mode Enabled',
            'recommendation': 'Disable debug mode in production environments. Use environment-based configuration.',
            'cwe_id': 'CWE-489'
        }
    }
    
    @classmethod
    def check(cls, code_or_file_changes, language=None, filename=None) -> List[SecurityIssue]:
        """
        Run security checks on code changes
        
        Args:
            code_or_file_changes: Either:
                - A string of code (when language and filename are provided)
                - List of dicts with {filename, additions: [{line_number, content}]}
            language: Optional language hint (used when code_or_file_changes is a string)
            filename: Optional filename (used when code_or_file_changes is a string)
            
        Returns:
            List of SecurityIssue findings
        """
        findings = []
        
        # Handle string code input (for testing)
        if isinstance(code_or_file_changes, str):
            if not filename:
                filename = 'unknown'
            
            lines = code_or_file_changes.strip().split('\n')
            file_changes = [{
                'filename': filename,
                'additions': [
                    {'line_number': i + 1, 'content': line}
                    for i, line in enumerate(lines)
                ]
            }]
        else:
            file_changes = code_or_file_changes
        
        for file_change in file_changes:
            filename = file_change.get('filename', 'unknown')
            additions = file_change.get('additions', [])
            
            for addition in additions:
                line_number = addition.get('line_number', 0)
                content = addition.get('content', '')
                
                # Check against all security patterns
                for rule_name, rule_data in cls.SECURITY_PATTERNS.items():
                    for pattern in rule_data['patterns']:
                        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                        if match:
                            findings.append(SecurityIssue(
                                severity=rule_data['severity'],
                                title=rule_data['title'],
                                description=f"Security pattern '{rule_name}' detected in code change.",
                                file=filename,
                                line_number=line_number,
                                code_snippet=content.strip()[:200],  # Limit snippet length
                                recommendation=rule_data['recommendation'],
                                cwe_id=rule_data.get('cwe_id')
                            ))
                            break  # Only report once per line per rule
        
        logger.info(f"Rule-based security check found {len(findings)} issues")
        return findings
    
    @classmethod
    def check_file_content(cls, filename: str, content: str) -> List[SecurityIssue]:
        """
        Check entire file content for security issues
        
        Args:
            filename: Name of the file
            content: Full file content
            
        Returns:
            List of SecurityIssue findings
        """
        findings = []
        lines = content.split('\n')
        
        for line_number, line in enumerate(lines, start=1):
            for rule_name, rule_data in cls.SECURITY_PATTERNS.items():
                for pattern in rule_data['patterns']:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        findings.append(SecurityIssue(
                            severity=rule_data['severity'],
                            title=rule_data['title'],
                            description=f"Security pattern '{rule_name}' detected.",
                            file=filename,
                            line_number=line_number,
                            code_snippet=line.strip()[:200],
                            recommendation=rule_data['recommendation'],
                            cwe_id=rule_data.get('cwe_id')
                        ))
                        break
        
        return findings