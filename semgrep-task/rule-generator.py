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
    
    def validate_description(self, description: str) -> Dict:
        """
        Validate if the description is meaningful or garbage using AI
        
        Args:
            description: The rule description to validate
            
        Returns:
            Dictionary with validation results:
            {
                "is_valid": bool,
                "quality_score": int (0-100),
                "reason": str
            }
        """
        # Quick checks for obviously bad input
        if not description or len(description.strip()) < 5:
            return {
                "is_valid": False,
                "quality_score": 0,
                "reason": "Description is too short (minimum 5 characters)"
            }
        
        # Use AI to validate the description
        validation_prompt = f"""Analyze this rule description for quality and meaningfulness:
"{description}"

Is this a valid, meaningful code review rule description?
Respond with JSON only (no other text):
{{
  "is_valid": true/false,
  "quality_score": 0-100,
  "reason": "brief explanation"
}}

Examples of GARBAGE (invalid): random characters ("asdfgh zxcv"), nonsense words, unrelated topics, empty/vague requests.
Examples of VALID: "detect SQL injection", "find hardcoded passwords", "check for missing error handling".

Be strict. Quality score: 0-30=garbage, 31-60=poor, 61-80=good, 81-100=excellent.
"""
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a strict validator for code review rule descriptions. Return ONLY valid JSON."
                },
                {
                    "role": "user",
                    "content": validation_prompt
                }
            ],
            "temperature": 0.3,
            "max_tokens": 200
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=15)
            
            if response.status_code != 200:
                # If validation API fails, assume valid but warn
                return {
                    "is_valid": True,
                    "quality_score": 60,
                    "reason": "Could not validate description (API error), proceeding with generation"
                }
            
            result = response.json()
            validation_text = result['choices'][0]['message']['content'].strip()
            
            # Clean up JSON if wrapped in markdown
            if validation_text.startswith("```json"):
                validation_text = validation_text.split("```json")[1].split("```")[0].strip()
            elif validation_text.startswith("```"):
                validation_text = validation_text.split("```")[1].split("```")[0].strip()
            
            # Parse JSON response
            validation_result = json.loads(validation_text)
            return validation_result
            
        except Exception as e:
            # If validation fails, assume valid but warn
            print(f"⚠️ Validation error: {e}")
            return {
                "is_valid": True,
                "quality_score": 60,
                "reason": f"Validation check failed: {str(e)}, proceeding anyway"
            }
    
    def check_duplicates(self, rule_id: str, language: str, rules_dir: str = "rules", new_rule: Dict = None) -> Dict:
        """
        Check if a similar rule already exists in the rule file
        
        Args:
            rule_id: The ID of the new rule to check
            language: Programming language
            rules_dir: Directory containing rule files
            new_rule: The new rule dict to compare patterns/messages
            
        Returns:
            Dictionary with duplicate check results:
            {
                "has_duplicates": bool,
                "similar_rules": [list of similar rule IDs with reasons]
            }
        """
        rule_file = os.path.join(rules_dir, f"{language.lower()}-rules.yml")
        
        if not os.path.exists(rule_file):
            return {
                "has_duplicates": False,
                "similar_rules": []
            }
        
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                content = f.read()
                existing_rules = yaml.safe_load(content)
            
            if not existing_rules or 'rules' not in existing_rules:
                return {
                    "has_duplicates": False,
                    "similar_rules": []
                }
            
            similar_rules = []
            rules_list = existing_rules.get('rules', [])
            
            # Ensure rules_list is actually a list
            if not isinstance(rules_list, list):
                return {
                    "has_duplicates": False,
                    "similar_rules": [],
                    "error": "Rules format is invalid"
                }
            
            # Helper function to normalize patterns for comparison
            def normalize_pattern(pattern_str):
                """Normalize a pattern by removing variables and extra syntax"""
                if not isinstance(pattern_str, str):
                    return ""
                
                # Convert to lowercase
                p = pattern_str.lower()
                
                # Replace all metavariables ($VAR, $X, $Y, etc.) with a placeholder
                import re
                p = re.sub(r'\$\w+', '$VAR', p)
                
                # Remove common syntax elements
                p = p.replace('if ', '').replace('while ', '').replace(':', '')
                p = p.replace(' ', '').replace('\n', '').replace('\t', '')
                
                # Remove quotes
                p = p.replace('"', '').replace("'", '')
                
                return p
            
            # Helper function to check pattern similarity
            def patterns_overlap(patterns1, patterns2):
                """Check if two pattern lists have overlapping patterns"""
                if not patterns1 or not patterns2:
                    return False
                
                # Extract pattern strings from various formats
                def extract_patterns(p):
                    if isinstance(p, list):
                        result = []
                        for item in p:
                            if isinstance(item, dict):
                                if 'pattern' in item:
                                    result.append(str(item['pattern']))
                            elif isinstance(item, str):
                                result.append(item)
                        return result
                    return []
                
                patterns1_list = extract_patterns(patterns1)
                patterns2_list = extract_patterns(patterns2)
                
                # Normalize and compare
                normalized1 = [normalize_pattern(p) for p in patterns1_list]
                normalized2 = [normalize_pattern(p) for p in patterns2_list]
                
                # Check for matches
                for p1 in normalized1:
                    for p2 in normalized2:
                        # Check if patterns are very similar (substring or exact match)
                        if p1 and p2:
                            if p1 == p2 or (len(p1) > 5 and p1 in p2) or (len(p2) > 5 and p2 in p1):
                                return True
                            
                            # Check for high similarity (e.g., >= 70% character overlap)
                            if len(p1) > 5 and len(p2) > 5:
                                shorter = min(p1, p2, key=len)
                                longer = max(p1, p2, key=len)
                                matches = sum(c in longer for c in shorter)
                                similarity = matches / len(shorter)
                                if similarity >= 0.7:
                                    return True
                
                return False
            
            for rule in rules_list:
                # Safely check if rule is a dict
                if not isinstance(rule, dict):
                    continue
                
                reasons = []
                
                # Check 1: Exact ID match
                if rule.get('id') == rule_id:
                    reasons.append("exact ID match")
                
                # Check 2: Similar patterns (if new_rule provided)
                if new_rule and 'pattern-either' in new_rule and 'pattern-either' in rule:
                    if patterns_overlap(new_rule.get('pattern-either'), rule.get('pattern-either')):
                        reasons.append("similar patterns detected")
                
                # Check 3: Very similar messages (keyword overlap)
                if new_rule and 'message' in new_rule and 'message' in rule:
                    new_msg = str(new_rule.get('message', '')).lower()
                    existing_msg = str(rule.get('message', '')).lower()
                    
                    # Extract key words (ignore common words)
                    common_words = {'the', 'a', 'an', 'to', 'for', 'use', 'instead', 'of', 'with', 'is', 'are'}
                    new_words = set(new_msg.split()) - common_words
                    existing_words = set(existing_msg.split()) - common_words
                    
                    # If 50%+ of meaningful words overlap, consider similar
                    if new_words and existing_words:
                        overlap = len(new_words & existing_words) / min(len(new_words), len(existing_words))
                        if overlap > 0.5:
                            reasons.append(f"similar message ({int(overlap*100)}% keyword overlap)")
                
                if reasons:
                    similar_rules.append({
                        "id": rule.get('id', 'unknown'),
                        "reasons": reasons,
                        "patterns": rule.get('pattern-either', rule.get('pattern', [])),
                        "message": rule.get('message', ''),
                        "severity": rule.get('severity', 'WARNING')
                    })
            
            return {
                "has_duplicates": len(similar_rules) > 0,
                "similar_rules": similar_rules
            }
            
        except Exception as e:
            print(f"⚠️ Duplicate check error: {e}")
            return {
                "has_duplicates": False,
                "similar_rules": [],
                "error": str(e)
            }
        
    def generate_rule(self, 
                     description: str, 
                     language: str,
                     severity: str = "WARNING",
                     category: str = "best-practice",
                     validate: bool = True) -> Dict:
        """
        Generate a Semgrep rule from natural language description
        
        Args:
            description: Natural language description of what to detect
            language: Programming language (python, javascript, java, go, etc.)
            severity: Rule severity (ERROR, WARNING, INFO)
            category: Rule category (security, best-practice, performance, etc.)
            validate: Whether to validate the description first (default: True)
            
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
            
            # Handle case where AI returns a list (e.g., [- id: ...])
            if isinstance(rule_dict, list):
                if len(rule_dict) > 0:
                    rule_dict = rule_dict[0]
                else:
                    raise ValueError("Generated YAML is an empty list")
            
            # Ensure we have a dict
            if not isinstance(rule_dict, dict):
                raise ValueError(f"Generated YAML is not a valid rule (got {type(rule_dict).__name__})")
            
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
- ID: {language.lower()}-descriptive-name (e.g., {language.lower()}-hardcoded-password, {language.lower()}-sql-injection)
- Use pattern-either for multiple patterns when needed
- IMPORTANT: Quote all pattern values (e.g., pattern: "some code") to prevent YAML parsing errors with colons
- Message: Clear explanation of the issue and suggested fix
- Severity: {severity}
- Metadata: category={category} (add cwe if security-related, e.g., cwe: CWE-89 for SQL injection)

Return ONLY the YAML rule (single rule, not a list).
"""
        return prompt
    
    
    def _get_example(self, language: str) -> str:
        """Get ONE best example rule for the specified language"""
        
        examples = {
            "python": """- id: py-sql-injection
  pattern-either:
    - pattern: $CURSOR.execute("... " + $VAR + " ...")
    - pattern: $CURSOR.execute(f"... {$VAR} ...")
  message: "SQL injection vulnerability detected. Use parameterized queries (cursor.execute(query, params)) instead of string concatenation"
  languages: [python]
  severity: ERROR
  metadata:
    category: security
    cwe: CWE-89
""",
            "javascript": """- id: js-loose-equality
  pattern-either:
    - pattern: if ($X == $Y) { ... }
    - pattern: while ($X == $Y) { ... }
    - pattern: $VAR = $X == $Y
  message: "Use strict equality (===) instead of == to prevent unexpected type coercion"
  languages: [javascript, typescript]
  severity: WARNING
  metadata:
    category: best-practice
""",
            "java": """- id: java-no-system-out
  pattern-either:
    - pattern: System.out.println(...)
    - pattern: System.err.println(...)
  message: "Avoid System.out.println in production. Use proper logging framework (log4j, slf4j, logback)"
  languages: [java]
  severity: WARNING
  metadata:
    category: best-practice
""",
            "go": """- id: go-no-fmt-println
  pattern-either:
    - pattern: fmt.Println(...)
    - pattern: fmt.Printf(...)
    - pattern: fmt.Print(...)
  message: "Avoid fmt.Println in production. Use proper logging (log package or structured logger like zap, logrus)"
  languages: [go]
  severity: WARNING
  metadata:
    category: best-practice
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
    
    def preview_rule(self,
                    description: str,
                    language: str,
                    severity: str = "WARNING",
                    category: str = "best-practice",
                    rules_dir: str = "rules") -> Dict:
        """
        Generate a rule preview with validation and duplicate checking (without saving)
        
        Returns:
            Dictionary with rule, validation results, and duplicate warnings
        """
        # Validate description first
        validation = self.validate_description(description)
        
        # Generate the rule regardless (user can decide)
        rule = self.generate_rule(description, language, severity, category, validate=False)
        
        # Check for duplicates with the new rule for pattern comparison
        rule_id = rule.get('id', 'unknown')
        duplicates = self.check_duplicates(rule_id, language, rules_dir, new_rule=rule)
        
        # Convert rule to YAML for preview
        rule_yaml = yaml.dump([rule], default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        return {
            'rule': rule,
            'yaml': rule_yaml,
            'validation': validation,
            'duplicates': duplicates,
            'success': True
        }
    
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
    
    elif len(sys.argv) > 1 and sys.argv[1] == 'preview':
        # Preview mode - generate without saving
        # Output ONLY JSON (no headers) for backend parsing
        generator = RuleGenerator()
        
        if len(sys.argv) < 4:
            error_result = {
                'success': False,
                'error': 'Usage: python rule-generator.py preview <description> <language> [severity] [category]'
            }
            print(json.dumps(error_result, indent=2))
            sys.exit(1)
        
        description = sys.argv[2]
        language = sys.argv[3]
        severity = sys.argv[4] if len(sys.argv) > 4 else "WARNING"
        category = sys.argv[5] if len(sys.argv) > 5 else "security"
        
        try:
            result = generator.preview_rule(description, language, severity, category)
            # Output ONLY JSON for easy parsing
            print(json.dumps(result, indent=2))
        except Exception as e:
            error_result = {
                'success': False,
                'error': str(e)
            }
            print(json.dumps(error_result, indent=2))
            sys.exit(1)
    
    elif len(sys.argv) > 1 and sys.argv[1] == 'validate':
        # Validate mode - only validate description
        # Output ONLY JSON (no headers) for backend parsing
        generator = RuleGenerator()
        
        if len(sys.argv) < 3:
            error_result = {
                'is_valid': False,
                'quality_score': 0,
                'reason': 'Usage: python rule-generator.py validate <description>'
            }
            print(json.dumps(error_result, indent=2))
            sys.exit(1)
        
        description = sys.argv[2]
        
        try:
            validation = generator.validate_description(description)
            print(json.dumps(validation, indent=2))
        except Exception as e:
            error_result = {
                'is_valid': False,
                'quality_score': 0,
                'reason': str(e)
            }
            print(json.dumps(error_result, indent=2))
            sys.exit(1)
    
    elif len(sys.argv) > 1:
        # CLI usage with arguments - generate and save
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

