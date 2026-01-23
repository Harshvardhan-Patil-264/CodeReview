import os
import re
import json
import semgrep
import subprocess
import shutil
import pandas as pd
import sys
from pathlib import Path
from datetime import datetime, timedelta
from github_handler import process_input
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_semgrep_scan(target_path, rules_path="rules"):
    """
    Run Semgrep scan on the target directory
    
    Args:
        target_path: Path to the code directory to scan
        rules_path: Path to the rules directory
    """

SUPPORTED_EXTENSIONS = {
    '.js': 'javascript', '.ts': 'typescript', '.java': 'java',
    '.py': 'python', '.go': 'go'
}

REQUIRED_HEADER_FIELDS = {
    'Purpose': r'(?i)purpose\s*:',
    'Author': r'(?i)author\s*:',
    'Date Created': r'(?i)date\s*created\s*:',
}

REQUIRED_HISTORY_FIELDS = {
    'Modified by': r'(?i)modified\s+by',
    'Modified Date': r'(?i)modified\s+date',
    'Purpose': r'(?i)purpose',
}

class CodeReviewer:
    def __init__(self, target_path):
        self.script_dir = Path(__file__).parent.resolve()
        self.rules_dir = self.script_dir / "rules"
        self.common_rules = self.rules_dir / "common-rules.yml"
        self.reports_dir = self.script_dir / "reports"
        self.target_path = Path(target_path).resolve()
        self.results = []
        self.cached_findings = {} # Store pre-scanned Semgrep findings
        
        # Create reports directory if it doesn't exist
        self.reports_dir.mkdir(exist_ok=True)
        
        self.rule_map = {
            '.js': self.rules_dir / 'javascript-rules.yml',
            '.ts': self.rules_dir / 'javascript-rules.yml',
            '.py': self.rules_dir / 'python-rules.yml',
            '.go': self.rules_dir / 'go-rules.yml',
            '.java': self.rules_dir / 'java-rules.yml'
        }

    def run_eslint(self, file_path):
        """
        Run ESLint on JavaScript/TypeScript files and return findings
        """
        if file_path.suffix not in ['.js', '.ts', '.jsx', '.tsx']:
            return []
        
        try:
            # Run ESLint with JSON output
            # Note: ESLint returns exit code 1 when it finds issues, which is expected
            cmd = ['npx', 'eslint', '--format', 'json', str(file_path)]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                encoding='utf-8', 
                cwd=str(self.script_dir),
                shell=True  # Required for npx on Windows
            )
            
            # ESLint returns 0 (no issues), 1 (issues found), or 2 (error)
            # We want to parse output for both 0 and 1
            if result.returncode > 1:
                return []
            
            if not result.stdout.strip():
                return []
            
            data = json.loads(result.stdout)
            findings = []
            
            for file_result in data:
                for message in file_result.get('messages', []):
                    # Skip messages without a ruleId (parsing errors, etc.)
                    rule_id = message.get('ruleId')
                    if not rule_id:
                        continue
                    
                    # Convert ESLint severity to Semgrep-like severity
                    severity_map = {1: 'WARNING', 2: 'ERROR'}
                    severity = severity_map.get(message.get('severity', 1), 'INFO')
                    
                    findings.append({
                        "Timestamp": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "File": file_path.name,
                        "Line": message.get('line', 0),
                        "Rule ID": f"eslint-{rule_id}",
                        "Severity": severity,
                        "Message": message.get('message', 'ESLint issue detected')
                    })
            
            return findings
        except (json.JSONDecodeError, FileNotFoundError):
            # ESLint not available or JSON parse error
            return []
        except Exception:
            # Any other error
            return []




    def pre_scan_semgrep(self, specific_path=None):
        """
        Optimized: Runs Semgrep on the whole folder OR a single file.
        If specific_path is provided, it ONLY scans that one file.
        """
        scan_target = str(specific_path) if specific_path else str(self.target_path)
        
        configs_to_run = set()
        if self.common_rules.exists():
            configs_to_run.add(str(self.common_rules))
            
        # If single file, only load the rule relevant to that extension
        if specific_path and specific_path.suffix in self.rule_map:
            r_path = self.rule_map[specific_path.suffix]
            if r_path.exists():
                configs_to_run.add(str(r_path))
        else:
            # Folder scan: load everything
            for r_path in self.rule_map.values():
                if r_path.exists():
                    configs_to_run.add(str(r_path))

        # Find semgrep executable using PATH (finds Python314's working version)
        semgrep_cmd = shutil.which("semgrep")
        if not semgrep_cmd:
            # Fallback: try to find it manually
            semgrep_cmd = "semgrep"

        # COMMUNITY RULES APPROACH: Using comprehensive GitHub community rules
        # Repository: https://github.com/Harshvardhan-Patil-264/semgrep-rules
        # 4000+ rules covering all languages and security frameworks
        community_rules_dir = self.script_dir / "community-rules"
        
        # Scan with custom rules first
        for config in configs_to_run:
            cmd = [semgrep_cmd, "scan", "--no-git-ignore", "--config", config, "--json", scan_target]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                
            if res.stdout.strip():
                try:
                    data = json.loads(res.stdout)
                    for finding in data.get('results', []):
                        fname = Path(finding['path']).name
                        if fname not in self.cached_findings:
                            self.cached_findings[fname] = []
                        
                        self.cached_findings[fname].append({
                            "Timestamp": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "File": fname, "Line": finding['start']['line'],
                            "Rule ID": finding['check_id'], "Severity": finding['extra']['severity'],
                            "Message": finding['extra']['message']
                        })
                except json.JSONDecodeError:
                    pass
        
        # Scan with community rules for comprehensive coverage
        # OPTIMIZED: Scan entire language directory at once instead of subdirectory-by-subdirectory
        # This reduces 150+ scans to just 14 scans (10-20x faster!)
        # Scan with community rules for comprehensive coverage
        if community_rules_dir.exists():
            # 1. SMART LANGUAGE DETECTION
            # Map extensions to rule categories
            LANGUAGE_MAP = {
                '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
                '.py': 'python', '.java': 'java', '.go': 'go', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp', 
                '.rs': 'rust', '.tf': 'terraform', '.hcl': 'terraform', '.sh': 'bash', '.yaml': 'yaml', '.yml': 'yaml',
                '.dockerfile': 'dockerfile'
            }
            ALWAYS_RUN = ['generic']  # Always run generic rules (includes secrets detection) 
            
            # Detect active languages in scan target
            active_categories = set(ALWAYS_RUN)
            target_path = Path(scan_target)
            
            if target_path.is_file():
                ext = target_path.suffix.lower()
                if ext in LANGUAGE_MAP:
                    active_categories.add(LANGUAGE_MAP[ext])
                if target_path.name == 'Dockerfile':
                    active_categories.add('dockerfile')
            elif target_path.is_dir():
                # For directories, check file extensions (limit to avoid traversing huge trees)
                # Just check what extensions exist
                try:
                    for root, _, files in os.walk(target_path):
                        for file in files:
                            ext = Path(file).suffix.lower()
                            if ext in LANGUAGE_MAP:
                                active_categories.add(LANGUAGE_MAP[ext])
                            if file == 'Dockerfile':
                                active_categories.add('dockerfile')
                        # Stop after finding some languages to avoid full traversals on huge repos if needed
                        # But for thoroughness, better to scan. os.walk is fast enough for metadata.
                except Exception:
                    pass

            # Filter relevant categories
            all_categories = [
                "javascript", "python", "java", "go", "typescript", "ruby", "php", 
                "csharp", "rust", "terraform", "generic", "yaml", "dockerfile", "bash"
            ]
            
            final_categories = [c for c in all_categories if c in active_categories]
            print(f"[AutoReview] Detected languages: {list(active_categories)}.")
            
            # Collect language directories to scan
            # OPTIMIZED: Scan entire language directories instead of subdirectories
            # This provides 10-20x performance improvement while maintaining 100% rule coverage
            # Semgrep automatically scans all .yml files recursively in a directory
            scan_jobs = []
            
            for category in final_categories:
                category_path = community_rules_dir / category
                if category_path.exists() and category_path.is_dir():
                    scan_jobs.append(category_path)
            
            print(f"[AutoReview] Scanning {len(scan_jobs)} language directories in parallel...")


            # 2. PARALLEL SCANNING
            # Use ThreadPoolExecutor to run Semgrep scans concurrently
            # Higher worker count (8) since many scans are I/O bound or small
            
            def scan_directory(rules_dir):
                if rules_dir.exists() and rules_dir.is_dir():
                    try:
                        cmd = [semgrep_cmd, "scan", "--no-git-ignore", "--config", str(rules_dir), "--json", scan_target]
                        res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                        if res.stdout.strip():
                            return json.loads(res.stdout)
                    except Exception:
                        pass
                return None

            # Optimal workers: usually 2x CPU core count for this mix of I/O and CPU
            max_workers = min(16, os.cpu_count() * 2 if os.cpu_count() else 8)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_dir = {executor.submit(scan_directory, d): d for d in scan_jobs}
                
                for future in as_completed(future_to_dir):
                    try:
                        data = future.result()
                        if data:
                            for finding in data.get('results', []):
                                fname = Path(finding['path']).name
                                if fname not in self.cached_findings:
                                    self.cached_findings[fname] = []
                                
                                self.cached_findings[fname].append({
                                    "Timestamp": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    "File": fname, "Line": finding['start']['line'],
                                    "Rule ID": finding['check_id'], "Severity": finding['extra']['severity'],
                                    "Message": finding['extra']['message']
                                })
                    except Exception:
                        pass

    def extract_comment_blocks(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            blocks_with_lines = []
            if file_path.suffix in ['.js', '.ts', '.java', '.go']:
                for match in re.finditer(r'/\*+([\s\S]*?)\*+/', content):
                    start_line = content.count('\n', 0, match.start()) + 1
                    blocks_with_lines.append((match.group(1), start_line))
                return blocks_with_lines
            elif file_path.suffix == '.py':
                for match in re.finditer(r'((?:^[ \t]*#.*(?:\n|$))+)', content, flags=re.MULTILINE):
                    start_line = content.count('\n', 0, match.start()) + 1
                    clean_block = re.sub(r'^[ \t]*#+', '', match.group(1), flags=re.MULTILINE).strip()
                    blocks_with_lines.append((clean_block, start_line))
                return blocks_with_lines
            return []
        except Exception:
            return []

    def check_header_logic(self, file_path): 
        if file_path.suffix not in SUPPORTED_EXTENSIONS:
            return

        timestamp = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
        comment_blocks = self.extract_comment_blocks(file_path)
        actual_mod_dt = datetime.fromtimestamp(os.path.getmtime(file_path)).replace(second=0, microsecond=0)

        header_box_found = False
        vc_table_found = False

        for block, block_start_line in comment_blocks:
            if re.search(r'(?i)HEADER\s+COMMENT\s+BOX', block):
                header_box_found = True
                for field, pattern in REQUIRED_HEADER_FIELDS.items():
                    if not re.search(pattern, block):
                        self.results.append({
                            "Timestamp": timestamp, "File": file_path.name, "Line": block_start_line,
                            "Rule ID": "HEADER-FIELD", "Severity": "ERROR", 
                            "Message": f"Header Comment Box is missing required field: '{field}'"
                        })

            if re.search(r'(?i)VERSION\s+CONTROL\s+TABLE', block):
                vc_table_found = True
                for field, pattern in REQUIRED_HISTORY_FIELDS.items():
                    if not re.search(pattern, block):
                        self.results.append({
                            "Timestamp": timestamp, "File": file_path.name, "Line": block_start_line,
                            "Rule ID": "VCT-COLUMN", "Severity": "ERROR", 
                            "Message": f"Version Control Table is missing column: '{field}'"
                        })

                raw_lines = block.split('\n')
                all_found_dts = [] 
                for i, line in enumerate(raw_lines):
                    current_line_no = block_start_line + i
                    stripped_line = line.strip()
                    if not stripped_line or re.match(r'^\*+\s*/?$', stripped_line): continue
                    if "VERSION CONTROL" in stripped_line.upper(): continue
                    
                    if "---" in stripped_line:
                        if len(re.findall(r'-{3,}', stripped_line)) < 3 or stripped_line.count("|") < 4:
                            self.results.append({
                                "Timestamp": timestamp, "File": file_path.name, "Line": current_line_no,
                                "Rule ID": "HEADER-T-FMT", "Severity": "ERROR", 
                                "Message": f"Version Control Table formatting error: Row {current_line_no} has invalid separator format ('---')"
                            })
                    elif stripped_line.count("|") > 0 and stripped_line.count("|") < 4:
                        self.results.append({
                            "Timestamp": timestamp, "File": file_path.name, "Line": current_line_no,
                            "Rule ID": "HEADER-T-FMT", "Severity": "ERROR", 
                            "Message": f"Version Control Table formatting error: Row {current_line_no} missing separators ('|')"
                        })
                    
                    found_dt_strs = re.findall(r'(\d{2,4}-\d{2}-\d{2,4}\s+\d{1,2}:\d{2}\s?[apAP][mM]?)', stripped_line)
                    if not found_dt_strs:
                        found_dt_strs = re.findall(r'(\d{2,4}-\d{2}-\d{2,4})', stripped_line)

                    for dt_str in found_dt_strs:
                        fmts = ["%d-%m-%Y %I:%M%p", "%d-%m-%Y %I:%M %p", "%Y-%m-%d %I:%M%p", "%Y-%m-%d %I:%M %p", 
                                "%d-%m-%Y %H:%M", "%Y-%m-%d %H:%M", "%d-%m-%Y", "%Y-%m-%d"]
                        for fmt in fmts:
                            try:
                                parsed_dt = datetime.strptime(dt_str.strip(), fmt)
                                all_found_dts.append((parsed_dt, current_line_no, dt_str))
                                break
                            except ValueError: continue

                if all_found_dts:
                    latest_entry = max(all_found_dts, key=lambda x: x[0])
                    latest_dt, latest_line, latest_str = latest_entry
                    
                    # Calculate difference (Actual - Code)
                    time_diff_mins = (actual_mod_dt - latest_dt).total_seconds() / 60
                    
                    # Error if Code time is in the FUTURE (diff < 0) 
                    # OR if Code time is > 5 mins BEHIND (diff > 5)
                    if time_diff_mins < 0 or time_diff_mins > 10:
                        self.results.append({
                            "Timestamp": timestamp, "File": file_path.name, "Line": latest_line,
                            "Rule ID": "HEADER-D", "Severity": "ERROR",
                            "Message": f"In Version Control Table, the latest Modified Date/Time (Found: {latest_str}) "
                                       f"does not match actual Modified date file (Actual: {actual_mod_dt.strftime('%Y-%m-%d %I:%M %p')})."
                        })

        if not header_box_found:
            self.results.append({"Timestamp": timestamp, "File": file_path.name, "Line": 1, "Rule ID": "HEADER-BOX-MISSING", "Severity": "ERROR", "Message": "Header Comment Box not found in file."})
        if not vc_table_found:
            self.results.append({"Timestamp": timestamp, "File": file_path.name, "Line": 1, "Rule ID": "HEADER-T-MISSING", "Severity": "ERROR", "Message": "Version Control Table not found in file."})

    def review_file_fast(self, file_path):
        """Pulls findings from memory cache instead of running a subprocess."""
        # Add Semgrep findings from cache
        findings = self.cached_findings.get(file_path.name, [])
        self.results.extend(findings)
        
        # Add ESLint findings for JavaScript/TypeScript files
        eslint_findings = self.run_eslint(file_path)
        self.results.extend(eslint_findings)

    def export_report(self, file_path):
        if not self.results: return
        report_name = f"{file_path.stem}_Review.xlsx"
        report_path = self.reports_dir / report_name
        is_update = report_path.exists()
        
        df = pd.DataFrame(self.results)
        # Ensure 'Rule ID' exists, otherwise default to False for is_header
        if 'Rule ID' in df.columns:
            df['is_header'] = df['Rule ID'].str.contains('HEADER|VCT')
            df = df.sort_values(by=['is_header', 'Line'], ascending=[False, True]).drop(columns=['is_header'])
        
        try:
            df.to_excel(str(report_path), index=False)
            print(" " * 80, end="\r") 
            if is_update:
                print(f"[UPDATE] Updated report : reports/{report_name}")
            else:
                print(f"[SUCCESS] Created new report: reports/{report_name}")
        except PermissionError:
            updated_report_name = f"{file_path.stem}_Review_updated.xlsx"
            updated_report_path = self.reports_dir / updated_report_name
            df.to_excel(str(updated_report_path), index=False)
            print(" " * 80, end="\r") 
            print(f"⚠️ reports/{report_name} is opened. So created another file named reports/{updated_report_name}")
    
    def export_language_report(self, lang_name, file_count):
        """Export consolidated report for all files of a specific language"""
        if not self.results: return
        
        report_name = f"{lang_name.capitalize()}Test_Review.xlsx"
        report_path = self.reports_dir / report_name
        is_update = report_path.exists()
        
        df = pd.DataFrame(self.results)
        # Ensure 'Rule ID' exists, otherwise default to False for is_header
        if 'Rule ID' in df.columns:
            df['is_header'] = df['Rule ID'].str.contains('HEADER|VCT')
            df = df.sort_values(by=['is_header', 'File', 'Line'], ascending=[False, True, True]).drop(columns=['is_header'])
        
        try:
            df.to_excel(str(report_path), index=False)
            print(" " * 80, end="\r") 
            if is_update:
                print(f"[UPDATE] Updated report: reports/{report_name} ({file_count} files, {len(df)} findings)")
            else:
                print(f"[SUCCESS] Created new report: reports/{report_name} ({file_count} files, {len(df)} findings)")
        except PermissionError:
            updated_report_name = f"{lang_name.capitalize()}Test_Review_updated.xlsx"
            updated_report_path = self.reports_dir / updated_report_name
            df.to_excel(str(updated_report_path), index=False)
            print(" " * 80, end="\r") 
            print(f"⚠️ reports/{report_name} is opened. So created another file named reports/{updated_report_name}")


    def run(self):
        # Print initialization message at the very start
        print("[*] Initializing security engine... Please wait.", flush=True)
        
        # Gather all valid files first to decide strategy
        files_to_scan = []
        
        # Check if target is a single file or directory
        if self.target_path.is_file():
            # Single file mode
            if self.target_path.suffix in self.rule_map:
                files_to_scan.append(self.target_path)
        else:
            # Directory mode - walk the tree
            for root, dirs, files in os.walk(self.target_path):
                dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'venv', '__pycache__']]
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix in self.rule_map:
                        files_to_scan.append(file_path)

        print(f"[AutoReview] Found {len(files_to_scan)} files to scan")
        
        # STEP 1: Smart Scan Selection - Run Semgrep once on entire directory
        if len(files_to_scan) == 1:
            self.pre_scan_semgrep(specific_path=files_to_scan[0])
        elif len(files_to_scan) > 1:
            print(f"[AutoReview] Running optimized bulk scan...")
            self.pre_scan_semgrep()
        
        # STEP 2: Process files in parallel and generate reports
        print(f"[AutoReview] Generating {len(files_to_scan)} reports in parallel...")
        
        def process_single_file(file_path):
            """Process a single file and generate its report"""
            try:
                # Collect findings for this file
                results = []
                
                # Get Semgrep findings from cache
                findings = self.cached_findings.get(file_path.name, [])
                results.extend(findings)
                
                # Add ESLint findings for JavaScript/TypeScript
                eslint_findings = self.run_eslint(file_path)
                results.extend(eslint_findings)
                
                # Check header logic
                header_results = []
                temp_results = []
                # We need to temporarily store results since check_header_logic uses self.results
                saved_results = self.results
                self.results = temp_results
                self.check_header_logic(file_path)
                header_results.extend(self.results)
                self.results = saved_results
                results.extend(header_results)
                
                # Export report for this file
                if results:
                    self.results = results
                    self.export_report(file_path)
                    return (file_path.name, len(results), True)
                else:
                    return (file_path.name, 0, False)
            except Exception as e:
                print(f"[ERROR] Failed to process {file_path.name}: {e}")
                return (file_path.name, 0, False)
        
        # Use ThreadPoolExecutor for parallel processing
        # Limit workers to avoid overwhelming the system
        max_workers = min(10, len(files_to_scan))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_file = {executor.submit(process_single_file, fp): fp for fp in files_to_scan}
            
            # Process completed tasks
            completed = 0
            for future in as_completed(future_to_file):
                completed += 1
                filename, findings_count, success = future.result()
                # Show progress
                print(f"[{completed}/{len(files_to_scan)}] Processed {filename} ({findings_count} findings)", end="\r", flush=True)
        
        print("\n[DONE] All documents scanned successfully.")



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Code Review Tool - Supports local folders and GitHub repositories')
    parser.add_argument("path", help="Path to code directory OR GitHub repository URL")
    args = parser.parse_args()
    
    # Process input (local folder or GitHub URL)
    target_path, is_github, repo_info, github_handler = process_input(args.path)
    
    if target_path:
        try:
            if is_github:
                print(f"\n[REPO] Analyzing GitHub Repository: {repo_info['full_name']}")
                print(f"[URL] URL: {repo_info['url']}\n")
            
            # Run code review
            CodeReviewer(target_path).run()
            
        finally:
            # Cleanup if it was a GitHub repo
            if is_github and github_handler:
                github_handler.cleanup()
    else:
        print("❌ Invalid input. Please provide a valid folder path or GitHub URL.")
        sys.exit(1)

