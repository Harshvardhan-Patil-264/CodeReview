import os
import json
import subprocess
import pandas as pd
from pathlib import Path

class CodeReviewer:
    def __init__(self, target_path):
        self.script_dir = Path(__file__).parent.resolve()
        self.rules_dir = self.script_dir / "rules"
        self.common_rules = self.rules_dir / "common-rules.yml"
        self.header_script = self.script_dir / "header-validator.py"
        self.target_path = Path(target_path).resolve()
        
        self.results = []
        self.rule_map = {
            '.js': self.rules_dir / 'javascript-rules.yml',
            '.py': self.rules_dir / 'python-rules.yml',
            '.go': self.rules_dir / 'go-rules.yml',
            '.java': self.rules_dir / 'java-rules.yml'
        }

    def run(self):
        if not self.target_path.exists():
            print(f"Error: Path {self.target_path} not found.")
            return

        if self.target_path.is_dir():
            for root, _, files in os.walk(self.target_path):
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix in self.rule_map:
                        self.results = [] 
                        self.check_header(file_path)
                        self.review_file(file_path)
                        self.export_file_report(file_path)
        else:
            self.results = []
            self.check_header(self.target_path)
            self.review_file(self.target_path)
            self.export_file_report(self.target_path)

    def check_header(self, file_path):
        print(f"Validating Header: {file_path.name}")
        cmd = ["python", str(self.header_script), str(file_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        if result.stdout and "FAILED" in result.stdout:
            self.results.append({
                "Timestamp": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                "File": file_path.name,
                "Line": 1,
                "Rule ID": "HEADER-CHECK",
                "Severity": "ERROR",
                "Message": result.stdout.strip()
            })

    def review_file(self, file_path):
        specific_rule = self.rule_map.get(file_path.suffix)
        active_rules = [r for r in [specific_rule, self.common_rules] if r and r.exists()]

        for rule_file in active_rules:
            print(f"Scanning: {file_path.name} with {rule_file.name}")
            cmd = ["semgrep", "--config", str(rule_file), "--json", str(file_path)]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            if res.stdout:
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
                except: continue

    def export_file_report(self, file_path):
        if not self.results:
            return
        
        report_name = f"{file_path.stem}.xlsx"
        new_df = pd.DataFrame(self.results)

        # Check if the file already exists
        if os.path.exists(report_name):
            # Load the existing data
            existing_df = pd.read_excel(report_name)
            # Combine old data with new data
            final_df = pd.concat([existing_df, new_df], ignore_index=True)
            print(f"🔄 Updated existing report: {report_name}")
        else:
            final_df = new_df
            print(f"✨ Created new report: {report_name}")
        
        final_df.to_excel(report_name, index=False)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    CodeReviewer(parser.parse_args().path).run()