#!/usr/bin/env python3
"""
File Header Validator
Validates that all code files have mandatory header comments with required fields:
- Purpose/Description
- Author
- Date
- Modified By (change history)
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict

# File extensions to check
SUPPORTED_EXTENSIONS = {
    '.js': 'javascript',
    '.ts': 'typescript',
    '.java': 'java',
    '.py': 'python',
    '.go': 'go',
    '.c': 'c',
    '.cpp': 'cpp',
    '.h': 'header',
}

# Comment patterns for different languages
COMMENT_PATTERNS = {
    'javascript': r'^\s*/\*\*?(.*?)\*/|^\s*//\s*(.*?)$',
    'typescript': r'^\s*/\*\*?(.*?)\*/|^\s*//\s*(.*?)$',
    'java': r'^\s*/\*\*?(.*?)\*/|^\s*//\s*(.*?)$',
    'c': r'^\s*/\*\*?(.*?)\*/|^\s*//\s*(.*?)$',
    'cpp': r'^\s*/\*\*?(.*?)\*/|^\s*//\s*(.*?)$',
    'header': r'^\s*/\*\*?(.*?)\*/|^\s*//\s*(.*?)$',
    'python': r'^\s*#\s*(.*?)$|^\s*"""(.*?)"""|^\s*\'\'\'(.*?)\'\'\'',
    'go': r'^\s*/\*\*?(.*?)\*/|^\s*//\s*(.*?)$',
}

# Required fields in file header
REQUIRED_FIELDS = {
    'purpose': r'(?i)(purpose|description)\s*:\s*(.+)',
    'author': r'(?i)author\s*:\s*(.+)',
    'date': r'(?i)date\s*:\s*(.+)',
    'modified': r'(?i)(modified\s*by|modified|changes?)\s*:\s*(.+)',
}

class HeaderValidator:
    def __init__(self, directory: str, exclude_dirs: List[str] = None):
        self.directory = Path(directory)
        self.exclude_dirs = exclude_dirs or ['node_modules', '.git', 'dist', 'build', '__pycache__']
        self.errors = []
        self.warnings = []
        self.files_checked = 0
        self.files_passed = 0
        
    def should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on exclusion rules"""
        # Skip if in excluded directory
        for exclude_dir in self.exclude_dirs:
            if exclude_dir in file_path.parts:
                return True
        
        # Skip if extension not supported
        if file_path.suffix not in SUPPORTED_EXTENSIONS:
            return True
            
        return False
    
    def extract_header_comments(self, file_path: Path, language: str) -> str:
        """Extract header comments from the beginning of the file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Get first 50 lines or 2000 characters (whichever comes first)
            lines = content.split('\n')[:50]
            header_section = '\n'.join(lines)
            
            return header_section
            
        except Exception as e:
            self.errors.append(f"Error reading {file_path}: {str(e)}")
            return ""
    
    def validate_file_header(self, file_path: Path) -> Dict[str, bool]:
        """Validate that file has all required header fields"""
        language = SUPPORTED_EXTENSIONS.get(file_path.suffix)
        if not language:
            return {}
        
        header = self.extract_header_comments(file_path, language)
        
        results = {}
        for field_name, pattern in REQUIRED_FIELDS.items():
            match = re.search(pattern, header, re.MULTILINE | re.IGNORECASE)
            results[field_name] = match is not None
            
        return results
    
    def validate_directory(self) -> Tuple[int, int]:
        """Validate all files in directory"""
        print(f"\n{'='*70}")
        print(f"FILE HEADER VALIDATION REPORT")
        print(f"{'='*70}\n")
        print(f"Scanning directory: {self.directory}")
        print(f"Excluded directories: {', '.join(self.exclude_dirs)}\n")
        
        for file_path in self.directory.rglob('*'):
            if not file_path.is_file():
                continue
                
            if self.should_skip_file(file_path):
                continue
            
            self.files_checked += 1
            results = self.validate_file_header(file_path)
            
            missing_fields = [field for field, found in results.items() if not found]
            
            if missing_fields:
                relative_path = file_path.relative_to(self.directory)
                self.errors.append({
                    'file': str(relative_path),
                    'missing': missing_fields
                })
            else:
                self.files_passed += 1
        
        return self.files_checked, self.files_passed
    
    def print_report(self):
        """Print validation report"""
        print(f"{'='*70}")
        print(f"VALIDATION SUMMARY")
        print(f"{'='*70}\n")
        print(f"Total files checked: {self.files_checked}")
        print(f"Files passed: {self.files_passed}")
        print(f"Files failed: {len(self.errors)}\n")
        
        if self.errors:
            print(f"{'='*70}")
            print(f"FILES WITH MISSING HEADER INFORMATION")
            print(f"{'='*70}\n")
            
            for error in self.errors:
                print(f"[FAIL] {error['file']}")
                print(f"       Missing fields: {', '.join(error['missing'])}")
                print()
            
            print(f"\n{'='*70}")
            print(f"REQUIRED HEADER FORMAT")
            print(f"{'='*70}\n")
            print("""
For JavaScript/TypeScript/Java/C/C++:
/**
 * Purpose: Brief description of what this file does
 * Author: Your Name
 * Date: YYYY-MM-DD
 * Modified By: Name - YYYY-MM-DD - Description of changes
 */

For Python:
# Purpose: Brief description of what this file does
# Author: Your Name
# Date: YYYY-MM-DD
# Modified By: Name - YYYY-MM-DD - Description of changes

For Go:
// Purpose: Brief description of what this file does
// Author: Your Name
// Date: YYYY-MM-DD
// Modified By: Name - YYYY-MM-DD - Description of changes
            """)
            
            return 1  # Exit code 1 for failures
        else:
            print("[PASS] All files have proper header documentation!")
            return 0  # Exit code 0 for success


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Validate file headers for mandatory documentation fields'
    )
    parser.add_argument(
        'directory',
        nargs='?',
        default='code',
        help='Directory to scan (default: code)'
    )
    parser.add_argument(
        '--exclude',
        nargs='+',
        default=['node_modules', '.git', 'dist', 'build', '__pycache__'],
        help='Directories to exclude from scanning'
    )
    
    args = parser.parse_args()
    
    validator = HeaderValidator(args.directory, args.exclude)
    validator.validate_directory()
    exit_code = validator.print_report()
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
