# tests/test_diff_parser.py

"""Unit tests for DiffParser

Tests parsing of unified diff format, language detection,
and tracking of additions/deletions.
"""

import pytest
from app.utils.diff_parser import DiffParser, FileDiff, DiffHunk


# Sample unified diffs for testing
SAMPLE_DIFF_SIMPLE = r"""diff --git a/app/main.py b/app/main.py
index abc123..def456 100644
--- a/app/main.py
+++ b/app/main.py
@@ -1,5 +1,6 @@
 import os
 import sys
+from typing import List
 
 def main():
-    print("Hello")
+    print("Hello World")
"""

SAMPLE_DIFF_MULTIPLE_FILES = r"""diff --git a/src/security.py b/src/security.py
index 111111..222222 100644
--- a/src/security.py
+++ b/src/security.py
@@ -10,3 +10,4 @@ def check_auth():
     if user:
         return True
     return False
+    # TODO: Add rate limiting
diff --git a/src/utils.js b/src/utils.js
new file mode 100644
index 0000000..333333
--- /dev/null
+++ b/src/utils.js
@@ -0,0 +1,5 @@
+function formatDate(date) {
+    return date.toISOString();
+}
+
+module.exports = { formatDate };
"""

SAMPLE_DIFF_DELETIONS = r"""diff --git a/legacy/old_code.py b/legacy/old_code.py
deleted file mode 100644
index 444444..000000
--- a/legacy/old_code.py
+++ /dev/null
@@ -1,10 +0,0 @@
-# This is old code
-def deprecated_function():
-    pass
-
-class OldClass:
-    def __init__(self):
-        self.value = 42
-
-if __name__ == "__main__":
-    deprecated_function()
"""

SAMPLE_DIFF_MULTIPLE_HUNKS = r'''diff --git a/app/service.py b/app/service.py
index 555555..666666 100644
--- a/app/service.py
+++ b/app/service.py
@@ -5,7 +5,8 @@ import logging
 
 logger = logging.getLogger(__name__)
 
-def process_data(data):
+def process_data(data: dict) -> dict:
+    """Process incoming data"""
     result = {}
     for key, value in data.items():
         result[key] = value.upper()
@@ -25,6 +26,7 @@ class DataService:
    
     def save(self, item):
         self.items.append(item)
+        logger.info(f"Saved item: {item}")
     
     def get_all(self):
        return self.items
'''
class TestDiffParser:
    """Test suite for DiffParser"""
    
    @pytest.fixture
    def parser(self):
        """Create a DiffParser instance"""
        return DiffParser()
    
    # ========================================================================
    # Basic Parsing Tests
    # ========================================================================
    
    def test_parse_simple_diff(self, parser):
        """Test parsing a simple diff with one file"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        
        assert len(files) == 1
        assert files[0].filename == "app/main.py"
        assert files[0].old_path == "a/app/main.py"
        assert files[0].new_path == "b/app/main.py"
        assert files[0].status == "modified"
        assert len(files[0].hunks) == 1
    
    def test_parse_multiple_files(self, parser):
        """Test parsing a diff with multiple files"""
        files = parser.parse(SAMPLE_DIFF_MULTIPLE_FILES)
        
        assert len(files) == 2
        
        # First file - modified
        assert files[0].filename == "src/security.py"
        assert files[0].status == "modified"
        
        # Second file - new
        assert files[1].filename == "src/utils.js"
        assert files[1].status == "added"
    
    def test_parse_deleted_file(self, parser):
        """Test parsing a deleted file"""
        files = parser.parse(SAMPLE_DIFF_DELETIONS)
        
        assert len(files) == 1
        assert files[0].filename == "legacy/old_code.py"
        assert files[0].status == "deleted"
        assert files[0].new_path == "/dev/null"
    
    def test_parse_multiple_hunks(self, parser):
        """Test parsing a file with multiple hunks"""
        files = parser.parse(SAMPLE_DIFF_MULTIPLE_HUNKS)
        
        assert len(files) == 1
        assert files[0].filename == "app/service.py"
        assert len(files[0].hunks) == 2
        
        # First hunk
        hunk1 = files[0].hunks[0]
        assert hunk1.old_start == 5
        assert hunk1.new_start == 5
        
        # Second hunk
        hunk2 = files[0].hunks[1]
        assert hunk2.old_start == 25
        assert hunk2.new_start == 26
    
    def test_parse_empty_diff(self, parser):
        """Test parsing an empty diff"""
        files = parser.parse("")
        assert len(files) == 0
    
    # ========================================================================
    # Language Detection Tests
    # ========================================================================
    
    def test_detect_python(self, parser):
        """Test Python file detection"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        assert files[0].language == "python"
    
    def test_detect_javascript(self, parser):
        """Test JavaScript file detection"""
        files = parser.parse(SAMPLE_DIFF_MULTIPLE_FILES)
        # Second file is JavaScript
        assert files[1].language == "javascript"
    
    @pytest.mark.parametrize("filename,expected_language", [
        ("test.py", "python"),
        ("main.js", "javascript"),
        ("app.ts", "typescript"),
        ("server.go", "go"),
        ("script.rb", "ruby"),
        ("config.json", "json"),
        ("styles.css", "css"),
        ("index.html", "html"),
        ("Main.java", "java"),
        ("program.cpp", "cpp"),
        ("script.sh", "shell"),
        ("config.yml", "yaml"),
        ("data.xml", "xml"),
        ("app.rs", "rust"),
        ("component.jsx", "javascript"),
        ("Component.tsx", "typescript"),
        ("README.md", "markdown"),
        ("unknown.xyz", "unknown"),
    ])
    def test_language_detection(self, parser, filename, expected_language):
        """Test language detection for various file types"""
        diff = f"""diff --git a/{filename} b/{filename}
index 111111..222222 100644
--- a/{filename}
+++ b/{filename}
@@ -1,1 +1,2 @@
 test
+addition
"""
        files = parser.parse(diff)
        assert files[0].language == expected_language
    
    # ========================================================================
    # Additions/Deletions Tracking Tests
    # ========================================================================
    
    def test_track_additions(self, parser):
        """Test tracking added lines"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        
        additions = files[0].additions
        # Should have added lines (import and modified print)
        assert len(additions) > 0
        # Line 3 should have the new import
        assert any(item['line_number'] == 3 for item in additions)
    
    def test_track_deletions(self, parser):
        """Test tracking deleted lines"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        
        deletions = files[0].deletions
        # Should have deleted lines (old print statement)
        assert len(deletions) > 0
    
    def test_track_file_deletion(self, parser):
        """Test tracking complete file deletion"""
        files = parser.parse(SAMPLE_DIFF_DELETIONS)
        
        # Deleted file should have many deletions
        assert len(files[0].deletions) == 10
        # Should have no additions
        assert len(files[0].additions) == 0
    
    def test_track_file_addition(self, parser):
        """Test tracking complete file addition"""
        files = parser.parse(SAMPLE_DIFF_MULTIPLE_FILES)
        
        # New file (utils.js) is second
        new_file = files[1]
        
        # Should have additions
        assert len(new_file.additions) == 5
        # Should have no deletions
        assert len(new_file.deletions) == 0
    
    def test_get_added_code(self, parser):
        """Test retrieving added code lines"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        
        added_code = files[0].get_added_code()
        
        # Should contain the new import
        assert any("from typing import List" in line for line in added_code)
        # Should contain the modified print
        assert any("Hello World" in line for line in added_code)
    
    def test_get_deleted_code(self, parser):
        """Test retrieving deleted code lines"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        
        deleted_code = files[0].get_deleted_code()
        
        # Should contain the old print statement
        assert any("Hello" in line for line in deleted_code)
    
    # ========================================================================
    # Hunk Parsing Tests
    # ========================================================================
    
    def test_hunk_header_parsing(self, parser):
        """Test parsing hunk headers"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        hunk = files[0].hunks[0]
        
        # Check hunk header values
        assert hunk.old_start == 1
        assert hunk.old_count == 5
        assert hunk.new_start == 1
        assert hunk.new_count == 6
    
    def test_hunk_content(self, parser):
        """Test hunk content"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        hunk = files[0].hunks[0]
        
        # Hunk should have content lines
        assert len(hunk.lines) > 0
        
        # Check for specific line types
        has_addition = any(line.startswith('+') for line in hunk.lines if line)
        has_deletion = any(line.startswith('-') for line in hunk.lines if line)
        has_context = any(line.startswith(' ') for line in hunk.lines if line)
        
        assert has_addition
        assert has_deletion
        assert has_context
    
    # ========================================================================
    # Edge Cases
    # ========================================================================
    
    def test_parse_diff_without_newline_at_end(self, parser):
        """Test parsing diff without newline at end of file"""
        diff = """diff --git a/test.txt b/test.txt
index 111111..222222 100644
--- a/test.txt
+++ b/test.txt
@@ -1,1 +1,1 @@
-old content
\\ No newline at end of file
+new content
\\ No newline at end of file"""
        
        files = parser.parse(diff)
        assert len(files) == 1
    
    def test_parse_binary_file(self, parser):
        """Test parsing binary file diff"""
        diff = """diff --git a/image.png b/image.png
index 111111..222222 100644
Binary files a/image.png and b/image.png differ
"""
        files = parser.parse(diff)
        # Should still parse but may have no hunks
        assert len(files) == 1
    
    def test_parse_renamed_file(self, parser):
        """Test parsing renamed file"""
        diff = """diff --git a/old_name.py b/new_name.py
similarity index 100%
rename from old_name.py
rename to new_name.py
"""
        files = parser.parse(diff)
        assert len(files) == 1
        assert files[0].status == "renamed"
    
    def test_stats_calculation(self, parser):
        """Test additions and deletions stats"""
        files = parser.parse(SAMPLE_DIFF_SIMPLE)
        
        total_additions = sum(len(f.additions) for f in files)
        total_deletions = sum(len(f.deletions) for f in files)
        
        # Should have some additions and deletions
        assert total_additions > 0
        assert total_deletions > 0


# Run tests with: pytest tests/test_diff_parser.py -v
