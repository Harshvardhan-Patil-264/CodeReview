import React, { useState } from 'react';
import '../styles/RuleGenerator.css';
import { previewRule, confirmRule } from '../services/apiService';

function RuleGenerator() {
    const [formData, setFormData] = useState({
        description: '',
        language: 'python',
        severity: 'WARNING',
        category: 'security'
    });
    const [isGenerating, setIsGenerating] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [previewData, setPreviewData] = useState(null);
    const [savedResult, setSavedResult] = useState(null);
    const [error, setError] = useState(null);

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
        // Clear preview when form changes
        if (previewData) {
            setPreviewData(null);
        }
    };

    const handlePreview = async (e) => {
        e.preventDefault();
        setIsGenerating(true);
        setError(null);
        setPreviewData(null);
        setSavedResult(null);

        try {
            const response = await previewRule(formData);
            setPreviewData(response);
        } catch (err) {
            // Extract detailed error message
            let errorMessage = 'Failed to preview rule';

            if (err.response?.data?.error?.message) {
                errorMessage = err.response.data.error.message;
            } else if (err.response?.data?.message) {
                errorMessage = err.response.data.message;
            } else if (err.message) {
                errorMessage = err.message;
            }

            // Add helpful hint for common issues
            if (errorMessage.includes('invalid YAML') || errorMessage.includes('YAML')) {
                errorMessage += '\n\n💡 Tip: The AI generated invalid syntax. Try rephrasing your description or selecting a different language.';
            } else if (errorMessage.includes('preview failed')) {
                errorMessage += '\n\n💡 Tip: Make sure your description matches the selected language (e.g., don\'t describe JavaScript features for Python rules).';
            }

            setError(errorMessage);
        } finally {
            setIsGenerating(false);
        }
    };

    const handleConfirm = async () => {
        if (!previewData || !previewData.rule) {
            setError('No rule to save. Please generate a preview first.');
            return;
        }

        setIsSaving(true);
        setError(null);

        try {
            const response = await confirmRule(previewData.rule, formData.language);
            setSavedResult(response);
            // Keep preview data to show the rule that was saved
        } catch (err) {
            setError(err.response?.data?.error?.message || err.message || 'Failed to save rule');
        } finally {
            setIsSaving(false);
        }
    };

    const handleReset = () => {
        setFormData({
            description: '',
            language: 'python',
            severity: 'WARNING',
            category: 'security'
        });
        setPreviewData(null);
        setSavedResult(null);
        setError(null);
    };

    // Helper to get quality score color
    const getQualityColor = (score) => {
        if (score >= 80) return '#10b981'; // green
        if (score >= 60) return '#f59e0b'; // yellow
        if (score >= 30) return '#f97316'; // orange
        return '#ef4444'; // red
    };

    // Helper to get validation status text
    const getValidationStatus = (validation) => {
        if (!validation) return null;

        const { is_valid, quality_score } = validation;

        if (quality_score >= 80) return { text: 'Excellent', emoji: '✅' };
        if (quality_score >= 60) return { text: 'Good', emoji: '👍' };
        if (quality_score >= 30) return { text: 'Poor Quality', emoji: '⚠️' };
        return { text: 'Garbage Input Detected', emoji: '❌' };
    };

    return (
        <div className="rule-generator">
            <div className="generator-header">
                <h2>🤖 AI Rule Generator</h2>
                <p>Generate custom Semgrep rules with validation and preview</p>
            </div>

            <form onSubmit={handlePreview} className="generator-form">
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

                <div className="button-row">
                    <button
                        type="submit"
                        className="btn-generate"
                        disabled={isGenerating || !formData.description.trim()}
                    >
                        {isGenerating ? '⚙️ Generating Preview...' : '🔍 Preview Rule'}
                    </button>

                    {(previewData || savedResult) && (
                        <button
                            type="button"
                            className="btn-reset"
                            onClick={handleReset}
                            disabled={isGenerating || isSaving}
                        >
                            🔄 New Rule
                        </button>
                    )}
                </div>
            </form>

            {error && (
                <div className="alert alert-error">
                    <strong>Error:</strong> {error}
                </div>
            )}

            {/* Validation Warning */}
            {previewData && previewData.validation && (
                <div className={`validation-card ${previewData.validation.quality_score < 50 ? 'warning' : 'info'}`}>
                    <div className="validation-header">
                        <h3>
                            {getValidationStatus(previewData.validation)?.emoji}
                            {' '}Validation Result
                        </h3>
                        <div
                            className="quality-score"
                            style={{ backgroundColor: getQualityColor(previewData.validation.quality_score) }}
                        >
                            Score: {previewData.validation.quality_score}/100
                        </div>
                    </div>
                    <p className="validation-reason">
                        <strong>Status:</strong> {getValidationStatus(previewData.validation)?.text}
                    </p>
                    <p className="validation-reason">
                        {previewData.validation.reason}
                    </p>

                    {previewData.validation.quality_score < 50 && (
                        <div className="warning-message">
                            ⚠️ <strong>Warning:</strong> This description may be garbage or low quality.
                            Please review and consider revising your description for better results.
                        </div>
                    )}
                </div>
            )}

            {/* Duplicate Warning */}
            {previewData && previewData.duplicates && previewData.duplicates.has_duplicates && (
                <div className="alert alert-warning duplicate-alert">
                    <h4>⚠️ Similar Rules Detected</h4>
                    <p>The following existing rules appear similar to your new rule. Review them before saving:</p>

                    {previewData.duplicates.similar_rules.map((dup, idx) => (
                        <div key={idx} className="duplicate-rule-card">
                            <div className="duplicate-header">
                                <code className="rule-id">{dup.id}</code>
                                <span className="similarity-badge">
                                    {dup.reasons.join(', ')}
                                </span>
                            </div>

                            {dup.message && (
                                <div className="duplicate-message">
                                    <strong>Message:</strong> {dup.message}
                                </div>
                            )}

                            {dup.patterns && dup.patterns.length > 0 && (
                                <details className="duplicate-patterns">
                                    <summary>View Patterns ({dup.patterns.length})</summary>
                                    <ul>
                                        {dup.patterns.map((pattern, pidx) => (
                                            <li key={pidx}>
                                                <code>{pattern.pattern || pattern}</code>
                                            </li>
                                        ))}
                                    </ul>
                                </details>
                            )}
                        </div>
                    ))}

                    <div className="duplicate-action-hint">
                        💡 <strong>You can still save</strong> this rule if you believe it's different enough or serves a different purpose.
                    </div>
                </div>
            )}

            {/* Preview Section */}
            {previewData && (
                <div className="result-container">
                    <div className="preview-header">
                        <h3>📋 Rule Preview</h3>
                        <p className="preview-hint">Review the generated rule below. Click "Confirm & Save" to add it to your rule file.</p>
                    </div>

                    {previewData.yaml && (
                        <div className="yaml-output">
                            <div className="output-header">
                                <h3>Generated YAML</h3>
                                <button
                                    className="btn-copy"
                                    onClick={() => navigator.clipboard.writeText(previewData.yaml)}
                                >
                                    📋 Copy
                                </button>
                            </div>
                            <pre><code>{previewData.yaml}</code></pre>
                        </div>
                    )}

                    {!savedResult && (
                        <div className="confirm-section">
                            <button
                                className="btn-confirm"
                                onClick={handleConfirm}
                                disabled={isSaving}
                            >
                                {isSaving ? '💾 Saving...' : '✅ Confirm & Save to File'}
                            </button>
                            <p className="confirm-hint">
                                This will add the rule to <code>rules/{formData.language}-rules.yml</code>
                            </p>
                        </div>
                    )}
                </div>
            )}

            {/* Success Message */}
            {savedResult && (
                <div className="alert alert-success">
                    ✅ Rule saved successfully to: <code>{savedResult.filePath}</code>
                </div>
            )}
        </div>
    );
}

export default RuleGenerator;
