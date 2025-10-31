# app/utils/performance_rules.py

"""Rule-Based Performance Checker

Pattern-based performance analysis for common issues
including N+1 queries, inefficient loops, blocking I/O, etc.
"""

from typing import List, Dict, Any
import re
import logging

from app.models.analysis import PerformanceIssue

logger = logging.getLogger(__name__)


class PerformanceChecker:
    """Rule-based performance issue detector"""
    
    # Performance anti-pattern detection rules
    PERFORMANCE_PATTERNS = {
        'n_plus_one_query': {
            'patterns': [
                r'for\s+\w+\s+in\s+.*:\s*\n\s+.*\.objects\.get\(',  # Django ORM in loop
                r'for\s+\w+\s+in\s+.*:\s*\n\s+.*\.filter\(',
                r'for\s+\w+\s+in\s+.*:\s*\n\s+.*SELECT.*FROM',  # Raw SQL in loop
                r'\.map\s*\([^)]*\.(get|find|filter)',  # Map with database calls
            ],
            'impact': 'HIGH',
            'title': 'Potential N+1 Query Problem',
            'estimated_impact': 'Can cause exponential increase in database queries (O(n) queries instead of O(1))',
            'recommendation': 'Use select_related(), prefetch_related() (Django), include() (ActiveRecord), or JOIN queries to fetch related data in a single query.'
        },
        'nested_loops': {
            'patterns': [
                r'for\s+\w+\s+in\s+.*:\s*\n\s+for\s+\w+\s+in\s+.*:\s*\n\s+for\s+\w+\s+in',  # Triple nested
                r'while.*:\s*\n\s+for\s+\w+\s+in\s+.*:\s*\n\s+for',  # While + double for
            ],
            'impact': 'HIGH',
            'title': 'Deeply Nested Loops',
            'estimated_impact': 'O(n³) or worse complexity - can cause severe performance degradation with large datasets',
            'recommendation': 'Refactor using data structures (sets, dicts), caching, or algorithmic improvements. Consider breaking into smaller functions or using generators.'
        },
        'large_loop': {
            'patterns': [
                r'for\s+\w+\s+in\s+range\s*\(\s*\d{5,}',  # Large range
                r'while.*:\s*\n.*\+=\s*1.*\n.*<\s*\d{5,}',  # Large while loop
            ],
            'impact': 'MEDIUM',
            'title': 'Large Loop Iteration',
            'estimated_impact': 'Processing large number of iterations may cause UI freezing or timeout',
            'recommendation': 'Consider batching, pagination, or async/background processing for large datasets.'
        },
        'blocking_io': {
            'patterns': [
                r'requests\.(get|post|put|delete)\s*\(',  # Synchronous HTTP
                r'urllib\.request\.urlopen\s*\(',
                r'open\s*\([^)]*\)\.read\s*\(\s*\)',  # Blocking file read
                r'time\.sleep\s*\(',  # Sleep in sync code
            ],
            'impact': 'HIGH',
            'title': 'Blocking I/O Operation',
            'estimated_impact': 'Thread/event loop blocking - reduces concurrency and responsiveness',
            'recommendation': 'Use async/await with aiohttp/httpx, asyncio.sleep(), or offload to background workers (Celery, RQ).'
        },
        'inefficient_string_concat': {
            'patterns': [
                r'for\s+\w+\s+in\s+.*:\s*\n\s+\w+\s*\+=\s*["\']',  # String concat in loop
                r'while.*:\s*\n.*\w+\s*\+=\s*str\(',
            ],
            'impact': 'MEDIUM',
            'title': 'Inefficient String Concatenation',
            'estimated_impact': 'O(n²) memory allocation - slow for large strings',
            'recommendation': 'Use list append + join(), StringIO, or f-strings for better performance.'
        },
        'missing_index': {
            'patterns': [
                r'\.filter\s*\([^)]*\w+__exact\s*=',  # Filter without index hint
                r'WHERE\s+\w+\s*=\s*\$\d+',  # SQL WHERE without index
            ],
            'impact': 'HIGH',
            'title': 'Potential Missing Database Index',
            'estimated_impact': 'Full table scan - O(n) instead of O(log n) for indexed lookups',
            'recommendation': 'Add database index on frequently queried columns. Use EXPLAIN to analyze query plans.'
        },
        'loading_all_records': {
            'patterns': [
                r'\.all\s*\(\s*\)\s*$',  # Loading all records
                r'SELECT\s+\*\s+FROM\s+\w+\s*$',  # SELECT * without WHERE
                r'\.objects\.filter\s*\(\s*\)\s*$',  # Empty filter
            ],
            'impact': 'HIGH',
            'title': 'Loading All Records Without Pagination',
            'estimated_impact': 'Memory overflow and slow response with large tables',
            'recommendation': 'Use pagination (limit/offset), cursor-based pagination, or streaming for large result sets.'
        },
        'synchronous_in_async': {
            'patterns': [
                r'async\s+def\s+\w+.*:\s*\n.*requests\.',  # Sync requests in async
                r'async\s+def\s+\w+.*:\s*\n.*open\s*\(',  # Sync file I/O in async
                r'async\s+def\s+\w+.*:\s*\n.*time\.sleep',  # Sync sleep in async
            ],
            'impact': 'HIGH',
            'title': 'Synchronous Call in Async Function',
            'estimated_impact': 'Blocks event loop - defeats purpose of async code',
            'recommendation': 'Use async libraries (aiohttp, aiofiles) or wrap blocking calls with run_in_executor().'
        },
        'inefficient_list_operations': {
            'patterns': [
                r'\w+\s+in\s+\[.*\]',  # Membership test in list
                r'for\s+\w+\s+in\s+.*:\s*\n\s+if\s+\w+\s+in\s+\w+:',  # Loop with in check
            ],
            'impact': 'MEDIUM',
            'title': 'Inefficient List Operations',
            'estimated_impact': 'O(n) lookup instead of O(1) with sets/dicts',
            'recommendation': 'Convert lists to sets for membership tests. Use dict lookups instead of linear search.'
        },
        'global_state_access': {
            'patterns': [
                r'global\s+\w+',  # Global variable
                r'globals\(\)\[',  # Accessing globals dict
            ],
            'impact': 'LOW',
            'title': 'Global State Access',
            'estimated_impact': 'Potential race conditions, difficult to optimize/cache',
            'recommendation': 'Pass state as parameters, use dependency injection, or encapsulate in classes.'
        }
    }
    
    @classmethod
    def check(cls, file_changes: List[Dict[str, Any]]) -> List[PerformanceIssue]:
        """
        Run performance checks on code changes
        
        Args:
            file_changes: List of dicts with {filename, additions: [{line_number, content}]}
            
        Returns:
            List of PerformanceIssue findings
        """
        findings = []
        
        for file_change in file_changes:
            filename = file_change.get('filename', 'unknown')
            additions = file_change.get('additions', [])
            
            # Combine consecutive lines for multi-line pattern matching
            full_content = '\n'.join([add.get('content', '') for add in additions])
            
            for addition in additions:
                line_number = addition.get('line_number', 0)
                content = addition.get('content', '')
                
                # Check against all performance patterns
                for rule_name, rule_data in cls.PERFORMANCE_PATTERNS.items():
                    for pattern in rule_data['patterns']:
                        # Check single line
                        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                        # Also check in full content for multi-line patterns
                        full_match = re.search(pattern, full_content, re.IGNORECASE | re.MULTILINE)
                        
                        if match or full_match:
                            findings.append(PerformanceIssue(
                                severity=rule_data['impact'].lower(),  # Convert impact to severity
                                impact=rule_data['impact'],
                                title=rule_data['title'],
                                description=f"Performance pattern '{rule_name}' detected in code change.",
                                file=filename,
                                line_number=line_number,
                                code_snippet=content.strip()[:200],
                                estimated_impact=rule_data['estimated_impact'],
                                recommendation=rule_data['recommendation']
                            ))
                            break  # Only report once per line per rule
        
        logger.info(f"Rule-based performance check found {len(findings)} issues")
        return findings
    
    @classmethod
    def check_file_content(cls, filename: str, content: str) -> List[PerformanceIssue]:
        """
        Check entire file content for performance issues
        
        Args:
            filename: Name of the file
            content: Full file content
            
        Returns:
            List of PerformanceIssue findings
        """
        findings = []
        lines = content.split('\n')
        
        for line_number, line in enumerate(lines, start=1):
            for rule_name, rule_data in cls.PERFORMANCE_PATTERNS.items():
                for pattern in rule_data['patterns']:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        findings.append(PerformanceIssue(
                            severity=rule_data['impact'].lower(),  # Convert impact to severity
                            impact=rule_data['impact'],
                            title=rule_data['title'],
                            description=f"Performance pattern '{rule_name}' detected.",
                            file=filename,
                            line_number=line_number,
                            code_snippet=line.strip()[:200],
                            estimated_impact=rule_data['estimated_impact'],
                            recommendation=rule_data['recommendation']
                        ))
                        break
        
        return findings
        
        for file_data in changes.get('files', []):
            file_name = file_data['name']
            additions = file_data.get('additions', [])
            
            for line_num, line in enumerate(additions, 1):
                for rule_name, rule_data in self.PERFORMANCE_PATTERNS.items():
                    for pattern in rule_data['patterns']:
                        if re.search(pattern, line):
                            findings.append(PerformanceFinding(
                                severity=rule_data['severity'],
                                title=rule_data['title'],
                                description=f"Detected in: {line.strip()[:50]}...",
                                file=file_name,
                                line_number=line_num,
                                code_snippet=line.strip(),
                                impact=rule_data['impact'],
                                recommendation=rule_data['recommendation']
                            ))
        
        return findings