# app/utils/diff_parser.py

"""Git Diff Parser

Parses unified diff format from GitHub PRs to extract file changes,
additions, deletions, and context lines for analysis.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class DiffHunk:
    """Represents a single hunk in a diff"""
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    header: str
    lines: List[str]
    
    @property
    def old_count(self) -> int:
        """Alias for old_lines for compatibility"""
        return self.old_lines
    
    @property
    def new_count(self) -> int:
        """Alias for new_lines for compatibility"""
        return self.new_lines


@dataclass
class FileDiff:
    """Represents changes to a single file"""
    filename: str
    old_filename: Optional[str]
    status: str  # 'added', 'deleted', 'modified', 'renamed'
    additions: List[Dict[str, Any]]  # [{line_number, content}]
    deletions: List[Dict[str, Any]]   # [{line_number, content}]
    hunks: List[DiffHunk]
    language: Optional[str] = None
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    
    def get_added_code(self) -> List[str]:
        """Get list of added code lines"""
        return [item['content'] for item in self.additions]
    
    def get_deleted_code(self) -> List[str]:
        """Get list of deleted code lines"""
        return [item['content'] for item in self.deletions]


class DiffParser:
    """Parse git unified diff format"""
    
    # Regex patterns for diff parsing
    FILE_HEADER_PATTERN = re.compile(r'^diff --git a/(.*?) b/(.*?)$')
    OLD_FILE_PATTERN = re.compile(r'^--- a/(.*)$|^--- /dev/null$')
    NEW_FILE_PATTERN = re.compile(r'^\+\+\+ b/(.*)$|^\+\+\+ /dev/null$')
    HUNK_HEADER_PATTERN = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$')
    
    # File extension to language mapping
    LANGUAGE_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.go': 'go',
        '.rs': 'rust',
        '.cpp': 'cpp',
        '.c': 'c',
        '.h': 'c',
        '.hpp': 'cpp',
        '.cs': 'csharp',
        '.rb': 'ruby',
        '.php': 'php',
        '.sql': 'sql',
        '.sh': 'shell',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.json': 'json',
        '.xml': 'xml',
        '.html': 'html',
        '.css': 'css',
        '.md': 'markdown',
    }
    
    @classmethod
    def parse(cls, diff_content: str) -> List[FileDiff]:
        """
        Parse unified diff content into structured FileDiff objects
        
        Args:
            diff_content: Git unified diff format string
            
        Returns:
            List of FileDiff objects with extracted changes
        """
        if not diff_content or not diff_content.strip():
            logger.warning("Empty diff content provided")
            return []
        
        file_diffs = []
        lines = diff_content.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # Look for file header
            file_match = cls.FILE_HEADER_PATTERN.match(line)
            if file_match:
                file_diff, next_i = cls._parse_file_diff(lines, i)
                if file_diff:
                    file_diffs.append(file_diff)
                i = next_i
            else:
                i += 1
        
        logger.info(f"Parsed {len(file_diffs)} file diffs")
        return file_diffs
    
    @classmethod
    def _parse_file_diff(cls, lines: List[str], start_idx: int) -> tuple[Optional[FileDiff], int]:
        """Parse a single file's diff"""
        i = start_idx
        
        # Parse file header
        file_match = cls.FILE_HEADER_PATTERN.match(lines[i])
        if not file_match:
            return None, i + 1
        
        old_filename = file_match.group(1)
        new_filename = file_match.group(2)
        i += 1
        
        # Track if this is a rename or binary file
        is_renamed = False
        is_binary = False
        
        # Skip extended headers (index, mode, etc.)
        while i < len(lines) and lines[i].startswith(('index ', 'new file', 'deleted file', 'old mode', 'new mode', 'similarity', 'rename', 'Binary')):
            if lines[i].startswith('rename'):
                is_renamed = True
            if lines[i].startswith('Binary'):
                is_binary = True
            i += 1
        
        # For binary files or files without hunks, create minimal diff
        if is_binary or (i < len(lines) and not lines[i].startswith('---')):
            import os
            _, ext = os.path.splitext(new_filename)
            language = cls.LANGUAGE_MAP.get(ext.lower(), 'unknown' if ext else None)
            
            # Determine status
            if is_renamed:
                status = 'renamed'
            elif is_binary:
                status = 'modified'
            else:
                status = 'modified'
            
            file_diff = FileDiff(
                filename=new_filename,
                old_filename=old_filename if old_filename != new_filename else None,
                status=status,
                additions=[],
                deletions=[],
                hunks=[],
                language=language,
                old_path=f"a/{old_filename}",
                new_path=f"b/{new_filename}"
            )
            return file_diff, i
        
        # Parse --- and +++ lines
        if i >= len(lines):
            return None, i
        
        old_file_match = cls.OLD_FILE_PATTERN.match(lines[i])
        if not old_file_match:
            return None, i
        i += 1
        
        if i >= len(lines):
            return None, i
        
        new_file_match = cls.NEW_FILE_PATTERN.match(lines[i])
        if not new_file_match:
            return None, i
        i += 1
        
        # Determine file status
        is_new_file = '/dev/null' in lines[i - 2]
        is_deleted_file = '/dev/null' in lines[i - 1]
        is_renamed = old_filename != new_filename and not is_new_file and not is_deleted_file
        
        # For deleted files, use old_filename as the filename
        if is_deleted_file:
            display_filename = old_filename
        else:
            display_filename = new_filename
        
        if is_new_file:
            status = 'added'
        elif is_deleted_file:
            status = 'deleted'
        elif is_renamed:
            status = 'renamed'
        else:
            status = 'modified'
        
        # Parse hunks
        hunks = []
        additions = []
        deletions = []
        
        while i < len(lines):
            line = lines[i]
            
            # Check for next file
            if cls.FILE_HEADER_PATTERN.match(line):
                break
            
            # Parse hunk
            hunk_match = cls.HUNK_HEADER_PATTERN.match(line)
            if hunk_match:
                hunk, add_lines, del_lines, next_i = cls._parse_hunk(lines, i)
                hunks.append(hunk)
                additions.extend(add_lines)
                deletions.extend(del_lines)
                i = next_i
            else:
                i += 1
        
        # Determine language
        import os
        _, ext = os.path.splitext(display_filename)
        language = cls.LANGUAGE_MAP.get(ext.lower(), 'unknown' if ext else None)
        
        # Set paths correctly for added/deleted files
        if is_new_file:
            old_path = '/dev/null'
            new_path = f"b/{new_filename}"
        elif is_deleted_file:
            old_path = f"a/{old_filename}"
            new_path = '/dev/null'
        else:
            old_path = f"a/{old_filename}"
            new_path = f"b/{new_filename}"
        
        file_diff = FileDiff(
            filename=display_filename,
            old_filename=old_filename if is_renamed else None,
            status=status,
            additions=additions,
            deletions=deletions,
            hunks=hunks,
            language=language,
            old_path=old_path,
            new_path=new_path
        )
        
        return file_diff, i
    
    @classmethod
    def _parse_hunk(cls, lines: List[str], start_idx: int) -> tuple[DiffHunk, List[Dict], List[Dict], int]:
        """Parse a single hunk"""
        i = start_idx
        hunk_match = cls.HUNK_HEADER_PATTERN.match(lines[i])
        
        old_start = int(hunk_match.group(1))
        old_lines = int(hunk_match.group(2) or '1')
        new_start = int(hunk_match.group(3))
        new_lines = int(hunk_match.group(4) or '1')
        header = hunk_match.group(5) or ''
        
        i += 1
        
        hunk_lines = []
        additions = []
        deletions = []
        
        current_old_line = old_start
        current_new_line = new_start
        
        while i < len(lines):
            line = lines[i]
            
            # End of hunk - next hunk or next file
            if line.startswith('@@') or cls.FILE_HEADER_PATTERN.match(line):
                break
            
            # Empty line or context line
            if not line or line.startswith(' '):
                hunk_lines.append(line)
                current_old_line += 1
                current_new_line += 1
            # Addition
            elif line.startswith('+'):
                content = line[1:]  # Remove '+'
                hunk_lines.append(line)
                additions.append({
                    'line_number': current_new_line,
                    'content': content
                })
                current_new_line += 1
            # Deletion
            elif line.startswith('-'):
                content = line[1:]  # Remove '-'
                hunk_lines.append(line)
                deletions.append({
                    'line_number': current_old_line,
                    'content': content
                })
                current_old_line += 1
            # No newline marker
            elif line.startswith('\\'):
                hunk_lines.append(line)
            else:
                # Context line without prefix
                hunk_lines.append(line)
                current_old_line += 1
                current_new_line += 1
            
            i += 1
            
            # Check if we've read enough lines based on hunk size
            # Count additions/context for new side, deletions/context for old side
            additions_count = len([l for l in hunk_lines if l.startswith('+')])
            deletions_count = len([l for l in hunk_lines if l.startswith('-')])
            context_count = len([l for l in hunk_lines if l.startswith(' ') or (not l.strip() and l)])
            
            # Break if we've processed expected lines
            if (additions_count + context_count >= new_lines and 
                deletions_count + context_count >= old_lines):
                break
        
        hunk = DiffHunk(
            old_start=old_start,
            old_lines=old_lines,
            new_start=new_start,
            new_lines=new_lines,
            header=header,
            lines=hunk_lines
        )
        
        return hunk, additions, deletions, i
    
    @classmethod
    def get_added_code(cls, file_diff: FileDiff) -> str:
        """Extract all added code from a file diff"""
        return '\n'.join([add['content'] for add in file_diff.additions])
    
    @classmethod
    def get_deleted_code(cls, file_diff: FileDiff) -> str:
        """Extract all deleted code from a file diff"""
        return '\n'.join([del_line['content'] for del_line in file_diff.deletions])
    
    @classmethod
    def get_file_summary(cls, file_diff: FileDiff) -> Dict[str, Any]:
        """Get summary statistics for a file diff"""
        return {
            'filename': file_diff.filename,
            'status': file_diff.status,
            'language': file_diff.language,
            'additions': len(file_diff.additions),
            'deletions': len(file_diff.deletions),
            'hunks': len(file_diff.hunks),
            'net_change': len(file_diff.additions) - len(file_diff.deletions)
        }