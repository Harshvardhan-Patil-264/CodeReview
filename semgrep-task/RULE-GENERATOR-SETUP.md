# AI-Powered Semgrep Rule Generator Setup

## 🎯 Overview

This tool allows users to create custom Semgrep rules using **natural language** instead of learning YAML syntax. It uses **Groq API** (free tier) to convert descriptions into valid Semgrep rules.

## 🚀 Quick Start

### 1. Get Groq API Key (100% Free)

1. Go to https://console.groq.com
2. Sign up with Google/GitHub (free)
3. Go to API Keys section
4. Create a new API key
5. Copy the key (starts with `gsk_...`)

**Free Tier Limits:**
- ✅ 14,400 requests per day
- ✅ 30 requests per minute
- ✅ No credit card required

### 2. Install Dependencies

```bash
pip install -r requirements-rule-generator.txt
```

### 3. Set API Key

**Option A: Environment Variable (Recommended)**
```bash
# Windows
set GROQ_API_KEY=gsk_your_api_key_here

# Linux/Mac
export GROQ_API_KEY=gsk_your_api_key_here
```

**Option B: Pass to Constructor**
```python
generator = RuleGenerator(api_key="gsk_your_api_key_here")
```

## 📖 Usage

### CLI Usage

```bash
# Run example
python rule-generator.py

# Start Flask API server
python rule-generator.py server
```

### Python API Usage

```python
from rule_generator import RuleGenerator

# Initialize
generator = RuleGenerator()

# Generate and save a rule
result = generator.generate_and_save(
    description="detect when someone uses print() in Python",
    language="python",
    severity="WARNING",
    category="best-practice"
)

print(f"Rule saved to: {result['file_path']}")
```

### Flask API Usage (For React Frontend)

**Start the server:**
```bash
python rule-generator.py server
```

**API Endpoints:**

#### 1. Generate and Save Rule
```bash
POST http://localhost:5000/api/generate-rule

Request Body:
{
  "description": "detect when someone uses eval() function",
  "language": "python",
  "severity": "ERROR",
  "category": "security"
}

Response:
{
  "rule": { ... },
  "file_path": "rules/python-rules.yml",
  "success": true
}
```

#### 2. Preview Rule (Don't Save)
```bash
POST http://localhost:5000/api/preview-rule

Request Body:
{
  "description": "detect console.log statements",
  "language": "javascript",
  "severity": "WARNING",
  "category": "best-practice"
}

Response:
{
  "rule": { ... },
  "yaml": "- id: custom-rule-...\n  pattern: ...",
  "success": true
}
```

## 🌐 Integration with React + Node.js

### React Frontend Example

```javascript
// RuleGeneratorForm.jsx
import React, { useState } from 'react';
import axios from 'axios';

function RuleGeneratorForm() {
  const [description, setDescription] = useState('');
  const [language, setLanguage] = useState('python');
  const [severity, setSeverity] = useState('WARNING');
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);

  const handlePreview = async () => {
    setLoading(true);
    try {
      const response = await axios.post('http://localhost:5000/api/preview-rule', {
        description,
        language,
        severity,
        category: 'best-practice'
      });
      setPreview(response.data);
    } catch (error) {
      console.error('Error:', error);
      alert('Failed to generate rule');
    }
    setLoading(false);
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const response = await axios.post('http://localhost:5000/api/generate-rule', {
        description,
        language,
        severity,
        category: 'best-practice'
      });
      alert('Rule saved successfully!');
      // Optionally save to your MySQL database via Node.js backend
    } catch (error) {
      console.error('Error:', error);
      alert('Failed to save rule');
    }
    setLoading(false);
  };

  return (
    <div className="rule-generator">
      <h2>Create Custom Rule</h2>
      
      <div className="form-group">
        <label>Describe what you want to detect:</label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="e.g., detect when someone uses print() in Python"
          rows={3}
        />
      </div>

      <div className="form-group">
        <label>Language:</label>
        <select value={language} onChange={(e) => setLanguage(e.target.value)}>
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="java">Java</option>
          <option value="go">Go</option>
        </select>
      </div>

      <div className="form-group">
        <label>Severity:</label>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="INFO">INFO</option>
          <option value="WARNING">WARNING</option>
          <option value="ERROR">ERROR</option>
        </select>
      </div>

      <div className="buttons">
        <button onClick={handlePreview} disabled={loading}>
          {loading ? 'Generating...' : 'Preview Rule'}
        </button>
        <button onClick={handleSave} disabled={loading || !preview}>
          Save Rule
        </button>
      </div>

      {preview && (
        <div className="preview">
          <h3>Generated Rule Preview:</h3>
          <pre>{preview.yaml}</pre>
        </div>
      )}
    </div>
  );
}

export default RuleGeneratorForm;
```

### Node.js Backend Integration (Optional)

```javascript
// routes/rules.js
const express = require('express');
const axios = require('axios');
const router = express.Router();

// Proxy to Python Flask API
router.post('/generate-rule', async (req, res) => {
  try {
    const response = await axios.post('http://localhost:5000/api/generate-rule', req.body);
    
    // Save to MySQL database
    const { rule, file_path } = response.data;
    await db.query(
      'INSERT INTO custom_rules (user_id, language, description, rule_yaml) VALUES (?, ?, ?, ?)',
      [req.user.id, req.body.language, req.body.description, JSON.stringify(rule)]
    );
    
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
```

## 📝 Example Natural Language Inputs

### Python Examples
- "detect when someone uses print() statements"
- "find SQL injection vulnerabilities with string concatenation"
- "detect usage of eval() function"
- "find hardcoded passwords or API keys"
- "detect missing error handling after function calls"

### JavaScript Examples
- "detect console.log statements"
- "find usage of var instead of const or let"
- "detect == instead of ==="
- "find missing error handling in promises"
- "detect eval() usage"

### Java Examples
- "detect System.out.println usage"
- "find SQL injection with string concatenation"
- "detect missing try-catch blocks"
- "find hardcoded credentials"

### Go Examples
- "detect fmt.Println usage"
- "find missing error checks"
- "detect SQL injection vulnerabilities"
- "find goroutines without context"

## 🔧 Architecture

```
User (React Frontend)
    ↓
    ↓ HTTP Request
    ↓
Node.js Backend (Optional)
    ↓
    ↓ Proxy Request
    ↓
Python Flask API (rule-generator.py)
    ↓
    ↓ API Call
    ↓
Groq API (LLM)
    ↓
    ↓ Generated YAML
    ↓
Semgrep Rules File (python-rules.yml, etc.)
```

## 💡 Tips for Best Results

1. **Be specific** in your descriptions
   - ❌ "find bad code"
   - ✅ "detect when someone uses print() instead of logging"

2. **Mention the pattern** you want to detect
   - ❌ "security issues"
   - ✅ "SQL injection with string concatenation in database queries"

3. **Include context** if needed
   - ✅ "detect hardcoded API keys that start with 'sk_live_'"

## 🚨 Troubleshooting

### Error: "Groq API key is required"
- Set the `GROQ_API_KEY` environment variable
- Or pass it to the constructor: `RuleGenerator(api_key="your_key")`

### Error: "Generated invalid YAML"
- The LLM sometimes generates incorrect syntax
- Try rephrasing your description to be more specific
- Check the Groq API status

### CORS Error in React
- Make sure Flask-CORS is installed
- Check that the Flask server is running on port 5000

## 📊 Cost Analysis

**Groq Free Tier:**
- 14,400 requests/day = ~600 requests/hour
- Each rule generation = 1 request
- **Cost: $0** ✅

**Alternative: Hugging Face (if Groq limits reached):**
- Free tier available
- Slower than Groq
- No credit card required

## 🔐 Security Notes

- Never commit API keys to Git
- Use environment variables for production
- Consider rate limiting in production
- Validate generated rules before using in production

## 📚 Next Steps

1. Set up Groq API key
2. Test with CLI: `python rule-generator.py`
3. Start Flask server: `python rule-generator.py server`
4. Integrate with your React frontend
5. Add MySQL storage for custom rules (optional)

---

**Need Help?** Check the Groq documentation: https://console.groq.com/docs
