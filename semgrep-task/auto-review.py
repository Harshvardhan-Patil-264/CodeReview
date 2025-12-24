import os
import re
import json
import subprocess
import pandas as pd
from pathlib import Path

# --- Constants for Header Validation ---
SUPPORTED_EXTENSIONS = {
    '.js': 'javascript', '.ts': 'typescript', '.java': 'java',
    '.py': 'python', '.go': 'go'
}

# Basic mandatory fields
REQUIRED_FIELDS = {
    'Purpose': r'(?i)purpose\s*:',
    'Author': r'(?i)author\s*:',
    'Date Created': r'(?i)date\s*created\s*:',
}

class CodeReviewer:
    def __init__(self, target_path):
        self.script_dir = Path(__file__).parent.resolve()
        self.rules_dir = self.script_dir / "rules"
        self.common_rules = self.rules_dir / "common-rules.yml"
        self.target_path = Path(target_path).resolve()
        
        self.results = []
        
        self.rule_map = {
            '.js': self.rules_dir / 'javascript-rules.yml',
            '.ts': self.rules_dir / 'javascript-rules.yml',
            '.py': self.rules_dir / 'python-rules.yml',
            '.go': self.rules_dir / 'go-rules.yml',
            '.java': self.rules_dir / 'java-rules.yml'
        }

    def extract_header(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return '\n'.join(content.split('\n')[:50])
        except Exception:
            return ""

    def check_header(self, file_path):
        """Validates header with ONLY the requested custom error messages."""
        if file_path.suffix not in SUPPORTED_EXTENSIONS:
            return

        header_text = self.extract_header(file_path)
        timestamp = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 1. Check for the * box format (Restored as requested)
        has_star_box = re.search(r'\*{10,}', header_text)
        if not has_star_box:
            self.results.append({
                "Timestamp": timestamp,
                "File": file_path.name,
                "Line": 1,
                "Rule ID": "HEADER-FORMAT",
                "Severity": "ERROR",
                "Message": "Headers are not represented in * comment box"
            })

        # 2. Custom Mandatory Fields Check
        missing_fields = [field for field, pattern in REQUIRED_FIELDS.items() if not re.search(pattern, header_text)]

        if missing_fields:
            self.results.append({
                "Timestamp": timestamp,
                "File": file_path.name,
                "Line": 1,
                "Rule ID": "HEADER-CONTENT",
                "Severity": "ERROR",
                "Message": "Missing mandatory fields like Purpose, Author, Date Created inside * Header Comment box"
            })

        # 3. Custom Modification Table Check
        history_table_pattern = r'(?i)MODIFIED BY\s*\|\s*MODIFIED DATE\s*\|\s*PURPOSE'
        if not re.search(history_table_pattern, header_text):
            self.results.append({
                "Timestamp": timestamp,
                "File": file_path.name,
                "Line": 1,
                "Rule ID": "HEADER-TABLE",
                "Severity": "ERROR",
                "Message": "Modification table not created which includes columns as Modified by, Modified Date, Purpose"
            })

    def review_file(self, file_path):
        specific_rule = self.rule_map.get(file_path.suffix)
        active_configs = []
        if specific_rule and specific_rule.exists():
            active_configs.append(str(specific_rule))
        if self.common_rules.exists():
            active_configs.append(str(self.common_rules))

        if not active_configs:
            return

        for config_path in active_configs:
            cmd = ["semgrep", "--quiet", "--config", config_path, "--json", str(file_path)]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            if res.stdout.strip():
                try:
                    data = json.loads(res.stdout)
                    for finding in data.get('results', []):
                        self.results.append({
                            "Timestamp": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "File": file_path.name,
                            "Line": finding['start']['line'],
                            "Rule ID": finding['check_id'],
                            "Severity": finding['extra']['severity'],
                            "Message": finding['extra']['message']
                        })
                except Exception as e:
                    print(f"❌ Error parsing Semgrep output: {e}")

    def export_file_report(self, file_path):
        if not self.results: 
            return
        
        report_name = f"{file_path.stem}_Review.xlsx"
        new_df = pd.DataFrame(self.results).copy()
        report_exists = os.path.exists(report_name)

        if report_exists:
            try:
                existing_df = pd.read_excel(report_name)
                combined_df = pd.concat([existing_df, new_df], ignore_index=True)
                final_df = combined_df.drop_duplicates(subset=['File', 'Line', 'Message'], keep='last').copy()
                status_msg = f"🔄 Updated report: {report_name}"
            except Exception: 
                final_df = new_df
                status_msg = f"✨ Created new report (Recovery): {report_name}"
        else:
            final_df = new_df
            status_msg = f"✨ Created new report: {report_name}"

        # Filtering logic to ensure only your specific messages appear
        legacy_messages = [
            "not done in * comment box",
            "Headers not used for purpose, author, date created, date modified",
            "Headers not used for purpose, author, date created",
            "Missing mandatory fields or table: Purpose, Author, Date Created, History Table"
        ]
        final_df = final_df[~final_df['Message'].isin(legacy_messages)]

        final_df.loc[:, 'is_header'] = final_df['Rule ID'].str.contains('HEADER')
        final_df = final_df.sort_values(by=['is_header', 'Line'], ascending=[False, True]).drop(columns=['is_header'])

        cols = ['Timestamp'] + [c for c in final_df.columns if c != 'Timestamp']
        final_df[cols].to_excel(report_name, index=False)
        print(status_msg)

    def run(self):
        if not self.target_path.exists(): 
            print(f"❌ Target path {self.target_path} does not exist.")
            return

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'venv', '__pycache__']]
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix in self.rule_map:
                    self.results = [] 
                    self.check_header(file_path)
                    self.review_file(file_path)
                    self.export_file_report(file_path)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Path to file or directory to review")
    args = parser.parse_args()
    CodeReviewer(args.path).run()