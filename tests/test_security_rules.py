# tests/test_security_rules.py

"""Unit tests for SecurityChecker

Tests detection of common security vulnerabilities using
rule-based pattern matching.
"""

import pytest
from app.utils.security_rules import SecurityChecker
from app.models.analysis import Severity


class TestSecurityChecker:
    """Test suite for SecurityChecker"""
    
    @pytest.fixture
    def checker(self):
        """Create a SecurityChecker instance"""
        return SecurityChecker()
    
    # ========================================================================
    # CWE-89: SQL Injection Tests
    # ========================================================================
    
    def test_detect_sql_injection_string_concat(self, checker):
        """Test detection of SQL injection via string concatenation"""
        code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
'''
        issues = checker.check(code, "python", "app/db.py")
        
        sql_issues = [i for i in issues if i.cwe_id == "CWE-89"]
        assert len(sql_issues) > 0
        assert sql_issues[0].severity == Severity.CRITICAL
        assert "sql injection" in sql_issues[0].title.lower()
    
    def test_detect_sql_injection_format(self, checker):
        """Test detection of SQL injection via string formatting"""
        code = '''
def search_products(name):
    query = f"SELECT * FROM products WHERE name = '{name}'"
    return db.query(query)
'''
        issues = checker.check(code, "python", "app/products.py")
        
        sql_issues = [i for i in issues if i.cwe_id == "CWE-89"]
        assert len(sql_issues) > 0
        assert sql_issues[0].severity == Severity.CRITICAL
    
    def test_no_false_positive_parameterized_query(self, checker):
        """Test that parameterized queries don't trigger SQL injection"""
        code = '''
def get_user_safe(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))
'''
        issues = checker.check(code, "python", "app/db.py")
        
        sql_issues = [i for i in issues if i.cwe_id == "CWE-89"]
        # Should not detect SQL injection
        assert len(sql_issues) == 0
    
    # ========================================================================
    # CWE-798: Hardcoded Secrets Tests
    # ========================================================================
    
    def test_detect_hardcoded_api_key(self, checker):
        """Test detection of hardcoded API keys"""
        code = '''
import requests

API_KEY = "sk_live_1234567890abcdef"
headers = {"Authorization": f"Bearer {API_KEY}"}
'''
        issues = checker.check(code, "python", "app/config.py")
        
        secret_issues = [i for i in issues if i.cwe_id == "CWE-798"]
        assert len(secret_issues) > 0
        assert secret_issues[0].severity == Severity.CRITICAL
        assert "hardcoded" in secret_issues[0].title.lower()
    
    def test_detect_hardcoded_password(self, checker):
        """Test detection of hardcoded passwords"""
        code = '''
DATABASE_URL = "postgresql://admin:MyP@ssw0rd123@localhost/db"
'''
        issues = checker.check(code, "python", "settings.py")
        
        secret_issues = [i for i in issues if i.cwe_id == "CWE-798"]
        assert len(secret_issues) > 0
    
    def test_detect_aws_credentials(self, checker):
        """Test detection of AWS credentials"""
        code = '''
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
'''
        issues = checker.check(code, "python", "aws_config.py")
        
        secret_issues = [i for i in issues if i.cwe_id == "CWE-798"]
        assert len(secret_issues) > 0
    
    # ========================================================================
    # CWE-502: Unsafe Deserialization Tests
    # ========================================================================
    
    def test_detect_pickle_loads(self, checker):
        """Test detection of unsafe pickle.loads"""
        code = '''
import pickle

def load_data(data):
    return pickle.loads(data)
'''
        issues = checker.check(code, "python", "app/serializer.py")
        
        deser_issues = [i for i in issues if i.cwe_id == "CWE-502"]
        assert len(deser_issues) > 0
        assert deser_issues[0].severity == Severity.CRITICAL
    
    def test_detect_yaml_unsafe_load(self, checker):
        """Test detection of unsafe YAML loading"""
        code = '''
import yaml

def parse_config(content):
    return yaml.load(content)
'''
        issues = checker.check(code, "python", "config_parser.py")
        
        deser_issues = [i for i in issues if i.cwe_id == "CWE-502"]
        assert len(deser_issues) > 0
    
    # ========================================================================
    # CWE-78: Command Injection Tests
    # ========================================================================
    
    def test_detect_os_system(self, checker):
        """Test detection of os.system with user input"""
        code = '''
import os

def process_file(filename):
    os.system(f"cat {filename}")
'''
        issues = checker.check(code, "python", "app/processor.py")
        
        cmd_issues = [i for i in issues if i.cwe_id == "CWE-78"]
        assert len(cmd_issues) > 0
        assert cmd_issues[0].severity == Severity.CRITICAL
    
    def test_detect_subprocess_shell(self, checker):
        """Test detection of subprocess with shell=True"""
        code = '''
import subprocess

def run_command(cmd):
    subprocess.call(cmd, shell=True)
'''
        issues = checker.check(code, "python", "runner.py")
        
        cmd_issues = [i for i in issues if i.cwe_id == "CWE-78"]
        assert len(cmd_issues) > 0
    
    def test_detect_eval_exec(self, checker):
        """Test detection of eval/exec with user input"""
        code = '''
def calculate(expression):
    return eval(expression)
'''
        issues = checker.check(code, "python", "calculator.py")
        
        cmd_issues = [i for i in issues if i.cwe_id == "CWE-78"]
        assert len(cmd_issues) > 0
    
    # ========================================================================
    # CWE-79: XSS Vulnerability Tests
    # ========================================================================
    
    def test_detect_innerhtml_xss(self, checker):
        """Test detection of XSS via innerHTML"""
        code = '''
function displayMessage(msg) {
    document.getElementById('output').innerHTML = msg;
}
'''
        issues = checker.check(code, "javascript", "app.js")
        
        xss_issues = [i for i in issues if i.cwe_id == "CWE-79"]
        assert len(xss_issues) > 0
        assert xss_issues[0].severity == Severity.HIGH
    
    def test_detect_dangerously_set_inner_html(self, checker):
        """Test detection of React dangerouslySetInnerHTML"""
        code = '''
function UserComment({ comment }) {
    return <div dangerouslySetInnerHTML={{__html: comment}} />;
}
'''
        issues = checker.check(code, "javascript", "Comment.jsx")
        
        xss_issues = [i for i in issues if i.cwe_id == "CWE-79"]
        assert len(xss_issues) > 0
    
    # ========================================================================
    # CWE-22: Path Traversal Tests
    # ========================================================================
    
    def test_detect_path_traversal(self, checker):
        """Test detection of path traversal vulnerability"""
        code = '''
def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()
'''
        issues = checker.check(code, "python", "file_handler.py")
        
        path_issues = [i for i in issues if i.cwe_id == "CWE-22"]
        assert len(path_issues) > 0
        assert path_issues[0].severity == Severity.HIGH
    
    def test_detect_path_join_vulnerability(self, checker):
        """Test detection of unsafe path joining"""
        code = '''
import os

def get_user_file(user_id, filename):
    path = os.path.join("/uploads", filename)
    return open(path).read()
'''
        issues = checker.check(code, "python", "uploads.py")
        
        path_issues = [i for i in issues if i.cwe_id == "CWE-22"]
        assert len(path_issues) > 0
    
    # ========================================================================
    # CWE-327: Weak Cryptography Tests
    # ========================================================================
    
    def test_detect_md5_usage(self, checker):
        """Test detection of MD5 hash usage"""
        code = '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''
        issues = checker.check(code, "python", "auth.py")
        
        crypto_issues = [i for i in issues if i.cwe_id == "CWE-327"]
        assert len(crypto_issues) > 0
        assert crypto_issues[0].severity == Severity.HIGH
    
    def test_detect_sha1_usage(self, checker):
        """Test detection of SHA1 hash usage"""
        code = '''
import hashlib

token = hashlib.sha1(data).hexdigest()
'''
        issues = checker.check(code, "python", "tokens.py")
        
        crypto_issues = [i for i in issues if i.cwe_id == "CWE-327"]
        assert len(crypto_issues) > 0
    
    # ========================================================================
    # CWE-330: Insecure Random Tests
    # ========================================================================
    
    def test_detect_random_for_security(self, checker):
        """Test detection of random.random() for security purposes"""
        code = '''
import random

def generate_token():
    return str(random.random())
'''
        issues = checker.check(code, "python", "token_gen.py")
        
        random_issues = [i for i in issues if i.cwe_id == "CWE-330"]
        assert len(random_issues) > 0
        assert random_issues[0].severity == Severity.MEDIUM
    
    def test_detect_math_random_js(self, checker):
        """Test detection of Math.random() in JavaScript"""
        code = '''
function generateToken() {
    return Math.random().toString(36);
}
'''
        issues = checker.check(code, "javascript", "auth.js")
        
        random_issues = [i for i in issues if i.cwe_id == "CWE-330"]
        assert len(random_issues) > 0
    
    # ========================================================================
    # CWE-306: Missing Authentication Tests
    # ========================================================================
    
    def test_detect_missing_auth_decorator(self, checker):
        """Test detection of endpoints without authentication"""
        code = '''
@app.route('/admin/users', methods=['DELETE'])
def delete_user(user_id):
    User.delete(user_id)
    return {"status": "deleted"}
'''
        issues = checker.check(code, "python", "admin_routes.py")
        
        auth_issues = [i for i in issues if i.cwe_id == "CWE-306"]
        assert len(auth_issues) > 0
        assert auth_issues[0].severity == Severity.HIGH
    
    # ========================================================================
    # CWE-489: Debug Mode Tests
    # ========================================================================
    
    def test_detect_debug_mode_enabled(self, checker):
        """Test detection of debug mode in production"""
        code = '''
app = Flask(__name__)
app.config['DEBUG'] = True
'''
        issues = checker.check(code, "python", "app.py")
        
        debug_issues = [i for i in issues if i.cwe_id == "CWE-489"]
        assert len(debug_issues) > 0
        assert debug_issues[0].severity == Severity.MEDIUM
    
    # ========================================================================
    # Multiple Issues Tests
    # ========================================================================
    
    def test_detect_multiple_vulnerabilities(self, checker):
        """Test detection of multiple vulnerabilities in one file"""
        code = '''
import os
import hashlib

API_KEY = "sk_live_secret123"

def authenticate(username, password):
    # Weak crypto
    hash_pw = hashlib.md5(password.encode()).hexdigest()
    
    # SQL injection
    query = f"SELECT * FROM users WHERE user='{username}'"
    user = db.execute(query)
    
    # Command injection
    os.system(f"log_access {username}")
    
    return user
'''
        issues = checker.check(code, "python", "vulnerable.py")
        
        # Should detect multiple issue types
        assert len(issues) >= 4
        
        # Check for different CWE IDs
        cwe_ids = {issue.cwe_id for issue in issues}
        assert "CWE-89" in cwe_ids  # SQL injection
        assert "CWE-327" in cwe_ids  # Weak crypto
        assert "CWE-78" in cwe_ids  # Command injection
        assert "CWE-798" in cwe_ids  # Hardcoded secrets
    
    # ========================================================================
    # Edge Cases & Safe Code Tests
    # ========================================================================
    
    def test_safe_code_no_issues(self, checker):
        """Test that safe code doesn't trigger false positives"""
        code = '''
from cryptography.fernet import Fernet
import secrets

def generate_secure_token():
    return secrets.token_urlsafe(32)

def hash_password(password):
    # Using bcrypt (safe)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
'''
        issues = checker.check(code, "python", "secure.py")
        
        # Should have minimal or no critical issues
        critical_issues = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(critical_issues) == 0
    
    def test_empty_code(self, checker):
        """Test handling of empty code"""
        issues = checker.check("", "python", "empty.py")
        assert len(issues) == 0
    
    def test_comments_only(self, checker):
        """Test handling of code with only comments"""
        code = '''
# This is a comment
# Another comment
'''
        issues = checker.check(code, "python", "comments.py")
        assert len(issues) == 0
    
    def test_severity_levels(self, checker):
        """Test that different vulnerabilities have appropriate severity"""
        code = '''
import pickle
import random

# Critical: pickle.loads
data = pickle.loads(user_input)

# Medium: random for token
token = str(random.random())
'''
        issues = checker.check(code, "python", "mixed.py")
        
        critical = [i for i in issues if i.severity == Severity.CRITICAL]
        medium = [i for i in issues if i.severity == Severity.MEDIUM]
        
        assert len(critical) > 0
        assert len(medium) > 0


# Run tests with: pytest tests/test_security_rules.py -v
