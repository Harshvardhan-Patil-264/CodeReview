"""
AI-Powered Semgrep Rule Generator (Alternative Implementation)
Uses direct HTTP requests to Groq API to avoid Python 3.14 compatibility issues
"""

import os
import yaml
import json
import requests
from dotenv import load_dotenv
from typing import Dict, List, Optional

# Load environment variables from .env file
load_dotenv()


class RuleGenerator:
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the rule generator with Groq API
        
        Args:
            api_key: Groq API key (or set GROQ_API_KEY environment variable)
        """
        self.api_key = api_key or os.getenv('GROQ_API_KEY')
        if not self.api_key:
            raise ValueError("Groq API key is required. Set GROQ_API_KEY in .env file or pass it to constructor.")
        
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.3-70b-versatile"  # Updated to active model (Jan 2026)
        
    def generate_rule(self, 
                     description: str, 
                     language: str,
                     severity: str = "WARNING",
                     category: str = "best-practice") -> Dict:
        """
        Generate a Semgrep rule from natural language description
        
        Args:
            description: Natural language description of what to detect
            language: Programming language (python, javascript, java, go, etc.)
            severity: Rule severity (ERROR, WARNING, INFO)
            category: Rule category (security, best-practice, performance, etc.)
            
        Returns:
            Dictionary containing the generated Semgrep rule
        """
        
        # Create the prompt for the LLM
        prompt = self._create_prompt(description, language, severity, category)
        
        # Prepare the request
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert in creating Semgrep rules. Generate valid Semgrep YAML rules based on user descriptions. Return ONLY valid YAML, no explanations."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 1000
        }
        
        # Call Groq API
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            
            # Log the response for debugging
            if response.status_code != 200:
                error_detail = response.text
                print(f"❌ Groq API Error: {response.status_code}")
                print(f"Response: {error_detail}")
                raise Exception(f"Groq API returned {response.status_code}: {error_detail}")
            
            response.raise_for_status()
            result = response.json()
            rule_yaml = result['choices'][0]['message']['content'].strip()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Groq API request failed: {str(e)}")
        
        # Clean up the response (remove markdown code blocks if present)
        if rule_yaml.startswith("```yaml"):
            rule_yaml = rule_yaml.split("```yaml")[1].split("```")[0].strip()
        elif rule_yaml.startswith("```"):
            rule_yaml = rule_yaml.split("```")[1].split("```")[0].strip()
        
        # Parse YAML to validate
        try:
            rule_dict = yaml.safe_load(rule_yaml)
            return rule_dict
        except yaml.YAMLError as e:
            raise ValueError(f"Generated invalid YAML: {e}\n\nGenerated content:\n{rule_yaml}")
    
    def _create_prompt(self, description: str, language: str, severity: str, category: str) -> str:
        """Create the prompt for the LLM"""
        
        example = self._get_example(language)
        
        prompt = f"""You are a Semgrep expert. Create a production-ready rule for {language}.

TASK: {description}

FORMAT (follow this EXACTLY):
{example}

REQUIREMENTS:
- ID: {language.lower()}-rule-X-descriptive-name
- Use pattern-either for multiple patterns
- IMPORTANT: Quote all pattern values (e.g., pattern: "some code") to prevent YAML parsing errors with colons
- Message: "Rule X: [explain WHY bad] [suggest WHAT to do]"
- Severity: {severity}
- Metadata: category={category}, rule="{language.upper()} Rule X"

Return ONLY the YAML rule (single rule, not a list).
"""
        return prompt
    
    
    def _get_example(self, language: str) -> str:
        """Get ONE best example rule for the specified language"""
        
        examples = {
            "python": """- id: py-rule-18-sql-injection
  pattern-either:
    - pattern: $CURSOR.execute("... " + $VAR + " ...")
    - pattern: $CURSOR.execute(f"... {$VAR} ...")
  message: "Rule 18: SQL injection vulnerability. Use parameterized queries (cursor.execute(query, params))"
  languages: [python]
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-89
    rule: "PY Rule 18"
""",
            "javascript": """- id: js-rule-1-strict-equality-check
  pattern-either:
    - pattern: if ($X == $Y) { ... }
    - pattern: while ($X == $Y) { ... }
    - pattern: $VAR = $X == $Y
  message: "Rule 1: Use strict equality (===) instead of == to prevent unexpected type coercion"
  languages: [javascript, typescript]
  severity: WARNING
  metadata:
    category: best-practice
    rule: "JS Rule 1"
""",
            "java": """- id: java-rule-2-no-system-out
  pattern-either:
    - pattern: System.out.println(...)
    - pattern: System.err.println(...)
  message: "Rule 2: Avoid System.out.println in production. Use proper logging framework (log4j, slf4j)"
  languages: [java]
  severity: WARNING
  metadata:
    category: best-practice
    rule: "Java Rule 2"
""",
            "go": """- id: go-rule-20-no-fmt-println
  pattern-either:
    - pattern: fmt.Println(...)
    - pattern: fmt.Printf(...)
    - pattern: fmt.Print(...)
  message: "Go Rule 20: Avoid fmt.Println in production. Use proper logging (log package or structured logger)"
  languages: [go]
  severity: WARNING
  metadata:
    category: best-practice
    rule: "Go Rule 20"
"""
        }
        
        return examples.get(language.lower(), examples["python"])
    
    def add_rule_to_file(self, rule: Dict, language: str, rules_dir: str = "rules") -> str:
        """
        Add the generated rule to the appropriate language-specific YAML file
        WITHOUT reformatting existing rules
        
        Args:
            rule: The generated rule dictionary
            language: Programming language
            rules_dir: Directory containing rule files
            
        Returns:
            Path to the updated rule file
        """
        # Determine the rule file path
        rule_file = os.path.join(rules_dir, f"{language.lower()}-rules.yml")
        
        # Convert the new rule to YAML string
        new_rule_yaml = yaml.dump([rule], default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        # Remove the leading "- " from the YAML since we'll add it manually with proper indentation
        new_rule_yaml = new_rule_yaml.strip()
        if new_rule_yaml.startswith('- '):
            new_rule_yaml = new_rule_yaml[2:]  # Remove "- "
        
        # Indent the rule properly (2 spaces for YAML list item)
        indented_rule = '\n'.join(['  ' + line if line else line for line in new_rule_yaml.split('\n')])
        
        # Read existing file content
        if os.path.exists(rule_file):
            with open(rule_file, 'r', encoding='utf-8') as f:
                existing_content = f.read()
        else:
            existing_content = "rules:\n"
        
        # Append the new rule at the end
        # Make sure there's proper spacing
        if not existing_content.endswith('\n'):
            existing_content += '\n'
        
        # Add the new rule with proper formatting
        new_content = existing_content + '\n  # AI-Generated Rule\n  - ' + indented_rule.strip() + '\n'
        
        # Write back to file
        with open(rule_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        return rule_file
    
    def generate_and_save(self, 
                         description: str,
                         language: str,
                         severity: str = "WARNING",
                         category: str = "best-practice",
                         rules_dir: str = "rules") -> Dict:
        """
        Generate a rule and save it to the appropriate file
        
        Returns:
            Dictionary with 'rule' and 'file_path' keys
        """
        # Generate the rule
        rule = self.generate_rule(description, language, severity, category)
        
        # Save to file
        file_path = self.add_rule_to_file(rule, language, rules_dir)
        
        return {
            'rule': rule,
            'file_path': file_path,
            'success': True
        }


# Flask API endpoint for web integration
def create_flask_api():
    """Create a Flask API for the rule generator"""
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    
    app = Flask(__name__)
    CORS(app)  # Enable CORS for React frontend
    
    # Initialize rule generator
    try:
        generator = RuleGenerator()
        print("✅ Rule Generator initialized successfully")
        print(f"🔑 API Key loaded: {generator.api_key[:10]}...")
    except Exception as e:
        print(f"❌ Failed to initialize Rule Generator: {e}")
        raise
    
    @app.route('/api/generate-rule', methods=['POST'])
    def generate_rule_endpoint():
        """
        API endpoint to generate Semgrep rules
        
        Request body:
        {
            "description": "detect print statements",
            "language": "python",
            "severity": "WARNING",
            "category": "best-practice"
        }
        """
        try:
            data = request.json
            
            # Validate required fields
            if not data.get('description'):
                return jsonify({'error': 'Description is required'}), 400
            if not data.get('language'):
                return jsonify({'error': 'Language is required'}), 400
            
            # Generate and save rule
            result = generator.generate_and_save(
                description=data['description'],
                language=data['language'],
                severity=data.get('severity', 'WARNING'),
                category=data.get('category', 'best-practice'),
                rules_dir=data.get('rules_dir', 'rules')
            )
            
            return jsonify(result), 200
            
        except Exception as e:
            return jsonify({'error': str(e), 'success': False}), 500
    
    @app.route('/api/preview-rule', methods=['POST'])
    def preview_rule_endpoint():
        """
        API endpoint to preview a rule without saving
        
        Request body: same as generate-rule
        """
        try:
            data = request.json
            
            if not data.get('description'):
                return jsonify({'error': 'Description is required'}), 400
            if not data.get('language'):
                return jsonify({'error': 'Language is required'}), 400
            
            # Generate rule (don't save)
            rule = generator.generate_rule(
                description=data['description'],
                language=data['language'],
                severity=data.get('severity', 'WARNING'),
                category=data.get('category', 'best-practice')
            )
            
            # Convert to YAML string for preview
            rule_yaml = yaml.dump([rule], default_flow_style=False, sort_keys=False)
            
            return jsonify({
                'rule': rule,
                'yaml': rule_yaml,
                'success': True
            }), 200
            
        except Exception as e:
            return jsonify({'error': str(e), 'success': False}), 500
    
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({'status': 'healthy', 'api_key_set': bool(generator.api_key)}), 200
    
    return app


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Run Flask server
        print("🚀 Starting Rule Generator API Server...")
        print("=" * 60)
        app = create_flask_api()
        print("=" * 60)
        print("📡 Server running on http://localhost:5000")
        print("📝 Endpoints:")
        print("   POST /api/generate-rule - Generate and save rule")
        print("   POST /api/preview-rule - Preview rule without saving")
        print("   GET  /health - Health check")
        print("=" * 60)
        app.run(debug=True, port=5000, host='0.0.0.0')
    elif len(sys.argv) > 1:
        # CLI usage with arguments
        print("AI-Powered Semgrep Rule Generator")
        print("=" * 50)
        
        # Initialize generator
        generator = RuleGenerator()
        
        description = sys.argv[1]
        language = sys.argv[2] if len(sys.argv) > 2 else "python"
        
        print(f"\n[*] Generating rule for: {description}")
        print(f"[LANG] Language: {language}\n")
        
        try:
            result = generator.generate_and_save(
                description=description,
                language=language,
                severity="WARNING",
                category="security"
            )
            
            print("[SUCCESS] Rule generated successfully!")
            print(f"[FILE] Saved to: {result['file_path']}")
            print(f"\n[RULE] Generated rule:")
            print(yaml.dump([result['rule']], default_flow_style=False, sort_keys=False))
        except Exception as e:
            print(f"[ERROR] Error generating rule: {e}")

    else:
        # Interactive mode
        print("AI-Powered Semgrep Rule Generator")
        print("=" * 50)
        
        # Initialize generator
        generator = RuleGenerator()
        
        print("\nEnter rule details below:")
        description = input("📝 Rule Description: ")
        while not description.strip():
            print("❌ Description is required!")
            description = input("📝 Rule Description: ")
            
        language = input("🔤 Language (default: python): ").strip()
        if not language:
            language = "python"
        
        print(f"\nGenerating rule for: {description}")
        print(f"Language: {language}\n")
        
        try:
            result = generator.generate_and_save(
                description=description,
                language=language,
                severity="WARNING",
                category="security"
            )
            
            print("✅ Rule generated successfully!")
            print(f"📁 Saved to: {result['file_path']}")
            print(f"\n📋 Generated rule:")
            print(yaml.dump([result['rule']], default_flow_style=False, sort_keys=False))
        except Exception as e:
            print(f"❌ Error generating rule: {e}")
