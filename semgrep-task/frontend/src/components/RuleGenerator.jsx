import React, { useState } from 'react';
import '../styles/RuleGenerator.css';
import { generateRule } from '../services/apiService';

function RuleGenerator() {
    const [formData, setFormData] = useState({
        description: '',
        language: 'python',
        severity: 'WARNING',
        category: 'security'
    });
    const [isGenerating, setIsGenerating] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsGenerating(true);
        setError(null);
        setResult(null);

        try {
            const response = await generateRule(formData);
            setResult(response);
        } catch (err) {
            setError(err.response?.data?.error?.message || err.message || 'Failed to generate rule');
        } finally {
            setIsGenerating(false);
        }
    };

    return (
        <div className="rule-generator">
            <div className="generator-header">
                <h2>🤖 AI Rule Generator</h2>
                <p>Generate custom Semgrep rules using natural language descriptions</p>
            </div>

            <form onSubmit={handleSubmit} className="generator-form">
                <div className="form-group">
                    <label htmlFor="description">
                        Rule Description *
                        <span className="label-hint">Describe what you want to detect</span>
                    </label>
                    <textarea
                        id="description"
                        name="description"
                        value={formData.description}
                        onChange={handleInputChange}
                        placeholder="Example: Detect hardcoded API keys in JavaScript code"
                        rows="4"
                        required
                        disabled={isGenerating}
                    />
                </div>

                <div className="form-row">
                    <div className="form-group">
                        <label htmlFor="language">Language *</label>
                        <select
                            id="language"
                            name="language"
                            value={formData.language}
                            onChange={handleInputChange}
                            required
                            disabled={isGenerating}
                        >
                            <option value="python">Python</option>
                            <option value="javascript">JavaScript</option>
                            <option value="java">Java</option>
                            <option value="go">Go</option>
                        </select>
                    </div>

                    <div className="form-group">
                        <label htmlFor="severity">Severity</label>
                        <select
                            id="severity"
                            name="severity"
                            value={formData.severity}
                            onChange={handleInputChange}
                            disabled={isGenerating}
                        >
                            <option value="ERROR">Error</option>
                            <option value="WARNING">Warning</option>
                            <option value="INFO">Info</option>
                        </select>
                    </div>

                    <div className="form-group">
                        <label htmlFor="category">Category</label>
                        <select
                            id="category"
                            name="category"
                            value={formData.category}
                            onChange={handleInputChange}
                            disabled={isGenerating}
                        >
                            <option value="security">Security</option>
                            <option value="best-practice">Best Practice</option>
                            <option value="performance">Performance</option>
                        </select>
                    </div>
                </div>

                <button
                    type="submit"
                    className="btn-generate"
                    disabled={isGenerating || !formData.description.trim()}
                >
                    {isGenerating ? '⚙️ Generating Rule...' : '✨ Generate Rule'}
                </button>
            </form>

            {error && (
                <div className="alert alert-error">
                    <strong>Error:</strong> {error}
                </div>
            )}

            {result && (
                <div className="result-container">
                    <div className="alert alert-success">
                        ✅ Rule generated successfully! Saved to: <code>{result.filePath}</code>
                    </div>

                    {result.yaml && (
                        <div className="yaml-output">
                            <div className="output-header">
                                <h3>Generated YAML</h3>
                                <button
                                    className="btn-copy"
                                    onClick={() => navigator.clipboard.writeText(result.yaml)}
                                >
                                    📋 Copy
                                </button>
                            </div>
                            <pre><code>{result.yaml}</code></pre>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default RuleGenerator;
