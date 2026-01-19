import { useState } from "react";
import {
    Loader2,
    CheckCircle2,
    AlertCircle,
    Copy,
    RotateCcw,
    ChevronDown,
    ChevronUp,
} from "lucide-react";
import { ruleAPI } from "../../services/api";

const SimilarRuleItem = ({ rule }) => {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <div className="mb-3 bg-white border rounded-xl overflow-hidden">
            <button
                type="button"
                onClick={() => setIsOpen(!isOpen)}
                className="w-full flex items-center justify-between p-4 hover:bg-gray-50 transition text-left"
            >
                <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                        <code className="text-sm font-mono bg-gray-100 px-2 py-1 rounded">
                            {rule.id}
                        </code>
                        <span className="text-xs text-gray-600">
                            {rule.reasons.join(", ")}
                        </span>
                    </div>
                    {rule.message && (
                        <p className="text-sm text-gray-700 pr-4">
                            {rule.message}
                        </p>
                    )}
                </div>
                {isOpen ? (
                    <ChevronUp className="size-5 text-gray-400" />
                ) : (
                    <ChevronDown className="size-5 text-gray-400" />
                )}
            </button>

            {isOpen && rule.patterns && rule.patterns.length > 0 && (
                <div className="px-4 pb-4 border-t pt-4 bg-gray-50">
                    <div>
                        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                            Detected Patterns ({rule.patterns.length})
                        </p>
                        <div className="bg-gray-900 rounded-lg p-3 overflow-x-auto">
                            <ul className="space-y-2">
                                {rule.patterns.map((pattern, idx) => (
                                    <li key={idx} className="text-xs font-mono text-gray-300">
                                        {typeof pattern === "string"
                                            ? pattern
                                            : pattern.pattern || JSON.stringify(pattern)}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default function RuleGeneratorPage() {
    const [formData, setFormData] = useState({
        description: "",
        language: "python",
        severity: "WARNING",
        category: "security",
    });
    const [isGenerating, setIsGenerating] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [previewData, setPreviewData] = useState(null);
    const [savedResult, setSavedResult] = useState(null);
    const [error, setError] = useState(null);

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: value,
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
            const response = await ruleAPI.previewRule(formData);
            setPreviewData(response);
        } catch (err) {
            let errorMessage = "Failed to preview rule";

            if (err.response?.data?.error?.message) {
                errorMessage = err.response.data.error.message;
            } else if (err.response?.data?.message) {
                errorMessage = err.response.data.message;
            } else if (err.message) {
                errorMessage = err.message;
            }

            setError(errorMessage);
        } finally {
            setIsGenerating(false);
        }
    };

    const handleConfirm = async () => {
        if (!previewData || !previewData.rule) {
            setError("No rule to save. Please generate a preview first.");
            return;
        }

        setIsSaving(true);
        setError(null);

        try {
            const response = await ruleAPI.confirmRule(previewData.rule, formData.language);
            setSavedResult(response);
        } catch (err) {
            setError(
                err.response?.data?.error?.message || err.message || "Failed to save rule"
            );
        } finally {
            setIsSaving(false);
        }
    };

    const handleReset = () => {
        setFormData({
            description: "",
            language: "python",
            severity: "WARNING",
            category: "security",
        });
        setPreviewData(null);
        setSavedResult(null);
        setError(null);
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
    };

    const getQualityColor = (score) => {
        if (score >= 80) return "bg-green-100 text-green-700";
        if (score >= 60) return "bg-yellow-100 text-yellow-700";
        if (score >= 30) return "bg-orange-100 text-orange-700";
        return "bg-red-100 text-red-700";
    };

    return (
        <div className="px-8 py-8">
            {/* Form Card */}
            <div className="max-w-4xl mx-auto border rounded-2xl bg-white shadow-sm p-8">
                <form onSubmit={handlePreview} className="space-y-6">
                    {/* Description */}
                    <div>
                        <label className="block text-sm font-semibold text-gray-900 mb-2">
                            Rule Description *
                            <span className="text-gray-500 font-normal ml-2">
                                (Describe what you want to detect)
                            </span>
                        </label>
                        <textarea
                            name="description"
                            value={formData.description}
                            onChange={handleInputChange}
                            placeholder="Example: Detect hardcoded API keys in JavaScript code"
                            rows="4"
                            required
                            disabled={isGenerating}
                            className="w-full border rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-blue-300 disabled:bg-gray-100"
                        />
                    </div>

                    {/* Language, Severity, Category */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label className="block text-sm font-semibold text-gray-900 mb-2">
                                Language *
                            </label>
                            <select
                                name="language"
                                value={formData.language}
                                onChange={handleInputChange}
                                required
                                disabled={isGenerating}
                                className="w-full border rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-blue-300 disabled:bg-gray-100"
                            >
                                <option value="python">Python</option>
                                <option value="javascript">JavaScript</option>
                                <option value="java">Java</option>
                                <option value="go">Go</option>
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-semibold text-gray-900 mb-2">
                                Severity
                            </label>
                            <select
                                name="severity"
                                value={formData.severity}
                                onChange={handleInputChange}
                                disabled={isGenerating}
                                className="w-full border rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-blue-300 disabled:bg-gray-100"
                            >
                                <option value="ERROR">Error</option>
                                <option value="WARNING">Warning</option>
                                <option value="INFO">Info</option>
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-semibold text-gray-900 mb-2">
                                Category
                            </label>
                            <select
                                name="category"
                                value={formData.category}
                                onChange={handleInputChange}
                                disabled={isGenerating}
                                className="w-full border rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-blue-300 disabled:bg-gray-100"
                            >
                                <option value="security">Security</option>
                                <option value="best-practice">Best Practice</option>
                                <option value="performance">Performance</option>
                            </select>
                        </div>
                    </div>

                    {/* Buttons */}
                    <div className="flex gap-4">
                        <button
                            type="submit"
                            className="flex-1 py-3 rounded-xl bg-blue-600 text-white font-semibold hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                            disabled={isGenerating || !formData.description.trim()}
                        >
                            {isGenerating && <Loader2 className="size-5 animate-spin" />}
                            {isGenerating ? "Generating Preview..." : "Preview Rule"}
                        </button>

                        {(previewData || savedResult) && (
                            <button
                                type="button"
                                className="px-6 py-3 rounded-xl border bg-white text-gray-700 font-semibold hover:bg-gray-50 transition flex items-center gap-2"
                                onClick={handleReset}
                                disabled={isGenerating || isSaving}
                            >
                                <RotateCcw className="size-4" />
                                New Rule
                            </button>
                        )}
                    </div>
                </form>

                {/* Error Message */}
                {error && (
                    <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 flex items-start gap-3">
                        <AlertCircle className="size-5 shrink-0 mt-0.5" />
                        <div>
                            <strong>Error:</strong> {error}
                        </div>
                    </div>
                )}

                {/* Validation Results */}
                {previewData && previewData.validation && (
                    <div className={`mt-6 border rounded-xl p-6 ${previewData.validation.quality_score < 50 ? 'bg-yellow-50 border-yellow-200' : 'bg-blue-50 border-blue-200'}`}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-semibold text-gray-900">
                                Validation Result
                            </h3>
                            <span
                                className={`px-3 py-1 rounded-full text-sm font-semibold ${getQualityColor(previewData.validation.quality_score)}`}
                            >
                                Score: {previewData.validation.quality_score}/100
                            </span>
                        </div>
                        <p className="text-gray-700">{previewData.validation.reason}</p>
                        {previewData.validation.quality_score < 50 && (
                            <div className="mt-4 p-3 bg-yellow-100 border border-yellow-300 rounded-lg text-yellow-800 text-sm">
                                <strong>Warning:</strong> This description may be low quality.
                                Consider revising for better results.
                            </div>
                        )}
                        {previewData.validation.quality_score < 30 && (
                            <div className="mt-4 p-3 bg-red-100 border border-red-300 rounded-lg text-red-800 text-sm">
                                <strong>Critical:</strong> This description is too vague or unclear. Please provide more specific details about what you want to detect.
                            </div>
                        )}
                    </div>
                )}

                {/* Only show Similar Rules and YAML if quality score >= 30 */}
                {previewData && previewData.validation && previewData.validation.quality_score >= 30 && (
                    <>
                        {/* Duplicate Warning */}
                        {previewData.duplicates &&
                            previewData.duplicates.has_duplicates && (
                                <div className="mt-6 p-6 bg-amber-50 border border-amber-200 rounded-xl">
                                    <h4 className="text-lg font-semibold text-gray-900 mb-3">
                                        ⚠️ Similar Rules Detected
                                    </h4>
                                    <p className="text-gray-700 mb-4">
                                        The following existing rules appear similar. Review before
                                        saving:
                                    </p>

                                    {previewData.duplicates.similar_rules.map((dup, idx) => (
                                        <SimilarRuleItem key={idx} rule={dup} />
                                    ))}

                                    <p className="text-sm text-gray-600 mt-4">
                                        💡 You can still save this rule if it serves a different
                                        purpose.
                                    </p>
                                </div>
                            )}

                        {/* YAML Preview */}
                        <div className="mt-6">
                            <div className="flex items-center justify-between mb-3">
                                <h3 className="text-lg font-semibold text-gray-900">
                                    📋 Generated Rule (YAML)
                                </h3>
                                <button
                                    className="flex items-center gap-2 px-4 py-2 rounded-xl border bg-white text-gray-700 hover:bg-gray-50 transition text-sm"
                                    onClick={() => copyToClipboard(previewData.yaml)}
                                >
                                    <Copy className="size-4" />
                                    Copy
                                </button>
                            </div>
                            <div className="bg-gray-900 rounded-xl p-6 overflow-x-auto">
                                <pre className="text-sm text-gray-100 font-mono">
                                    {previewData.yaml}
                                </pre>
                            </div>

                            {!savedResult && (
                                <div className="mt-4">
                                    <button
                                        className="w-full py-3 rounded-xl bg-green-600 text-white font-semibold hover:bg-green-700 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                                        onClick={handleConfirm}
                                        disabled={isSaving}
                                    >
                                        {isSaving ? (
                                            <>
                                                <Loader2 className="size-5 animate-spin" />
                                                Saving...
                                            </>
                                        ) : (
                                            <>
                                                <CheckCircle2 className="size-5" />
                                                Confirm & Save to File
                                            </>
                                        )}
                                    </button>
                                    <p className="text-center text-sm text-gray-500 mt-2">
                                        This will add the rule to{" "}
                                        <code className="bg-gray-100 px-2 py-1 rounded">
                                            rules/{formData.language}-rules.yml
                                        </code>
                                    </p>
                                </div>
                            )}
                        </div>
                    </>
                )}

                {/* Success Message */}
                {savedResult && (
                    <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-xl text-green-700 flex items-start gap-3">
                        <CheckCircle2 className="size-5 shrink-0 mt-0.5" />
                        <div>
                            <strong>Success!</strong> Rule saved to:{" "}
                            <code className="bg-green-100 px-2 py-1 rounded">
                                {savedResult.filePath}
                            </code>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
