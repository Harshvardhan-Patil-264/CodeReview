import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
    ArrowLeft,
    CheckCircle2,
    FileSpreadsheet,
    Loader2,
    Download,
    Clock,
    XCircle,
    AlertCircle
} from "lucide-react";
import { scanAPI } from "../../services/api";

export default function ScanProgressPage() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const scanId = searchParams.get("scanId");

    const [scan, setScan] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [downloadingIndex, setDownloadingIndex] = useState(null);

    useEffect(() => {
        if (!scanId) {
            setError("No scan ID provided");
            setIsLoading(false);
            return;
        }

        loadScanDetails();

        // Poll for updates if scan is not completed
        const interval = setInterval(() => {
            if (scan?.status === "processing" || scan?.status === "pending") {
                loadScanDetails();
            }
        }, 3000);

        return () => clearInterval(interval);
    }, [scanId]);

    const loadScanDetails = async () => {
        if (!scanId) return;

        try {
            const response = await scanAPI.getScanById(scanId);
            console.log('[ScanProgressPage] Received response:', response);
            if (response.success) {
                console.log('[ScanProgressPage] Scan data:', response.scan);
                console.log('[ScanProgressPage] Report stats:', response.scan.reportStats);
                setScan(response.scan);
            }
        } catch (err) {
            console.error("Failed to load scan details:", err);
            setError("Failed to load scan details");
        } finally {
            setIsLoading(false);
        }
    };

    const handleDownloadReport = async (reportPath, index) => {
        if (!scanId) return;

        setDownloadingIndex(index);
        try {
            const blob = await scanAPI.downloadReportByIndex(scanId, index);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;

            // Extract filename from reportPath
            const filename = reportPath.split('/').pop() || `report-${index + 1}.xlsx`;
            a.download = filename;

            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (err) {
            console.error("Failed to download report:", err);
            alert("Failed to download report");
        } finally {
            setDownloadingIndex(null);
        }
    };

    const formatDuration = (ms) => {
        const seconds = (ms / 1000).toFixed(2);
        return `${seconds}s`;
    };

    if (isLoading) {
        return (
            <div className="min-h-screen bg-gray-50 px-4 py-8 flex items-center justify-center">
                <div className="text-center">
                    <Loader2 className="size-12 animate-spin mx-auto text-blue-600 mb-4" />
                    <p className="text-gray-600">Loading scan details...</p>
                </div>
            </div>
        );
    }

    if (error || !scan) {
        return (
            <div className="min-h-screen bg-gray-50 px-4 py-8">
                <div className="max-w-2xl mx-auto">
                    <button
                        onClick={() => navigate("/dashboard")}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl border bg-white hover:bg-gray-50 transition mb-6"
                    >
                        <ArrowLeft className="size-4" />
                        Dashboard
                    </button>

                    <div className="bg-white border rounded-2xl p-10 text-center">
                        <AlertCircle className="size-16 mx-auto text-red-500 mb-4" />
                        <h2 className="text-xl font-semibold text-gray-900 mb-2">Error</h2>
                        <p className="text-gray-600">{error || "Scan not found"}</p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-50 px-4 py-8">
            <div className="max-w-4xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                    <button
                        onClick={() => navigate("/dashboard")}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl border bg-white hover:bg-gray-50 transition"
                    >
                        <ArrowLeft className="size-4" />
                        Dashboard
                    </button>

                    <h1 className="text-2xl font-semibold text-gray-900">Scan Progress</h1>

                    <div className="w-[120px]" />
                </div>

                {/* Status Card */}
                <div className="bg-white border rounded-2xl shadow-sm p-8 mb-6">
                    <div className="text-center mb-6">
                        <h2 className="text-3xl font-bold text-gray-900 mb-2 flex items-center justify-center gap-3">
                            {scan.status === "completed" && (
                                <>
                                    Scan Completed <CheckCircle2 className="size-8 text-green-600" />
                                </>
                            )}
                            {scan.status === "failed" && (
                                <>
                                    Scan Failed <XCircle className="size-8 text-red-600" />
                                </>
                            )}
                            {(scan.status === "processing" || scan.status === "pending") && (
                                <>
                                    Scanning... <Loader2 className="size-8 animate-spin text-blue-600" />
                                </>
                            )}
                        </h2>

                        <p className="text-gray-600">
                            {scan.status === "completed" && "Your code review reports are ready."}
                            {scan.status === "failed" && scan.error}
                            {(scan.status === "processing" || scan.status === "pending") && "Please wait while we analyze your code."}
                        </p>
                    </div>

                    {/* Scan Info */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                        <div className="bg-blue-50 rounded-xl p-4 text-center">
                            <p className="text-sm text-gray-600 mb-1">Scan ID</p>
                            <p className="font-mono text-sm font-semibold text-gray-900 break-all">
                                {scan.id}
                            </p>
                        </div>

                        <div className="bg-purple-50 rounded-xl p-4 text-center">
                            <p className="text-sm text-gray-600 mb-1">Source</p>
                            <p className="font-semibold text-gray-900 break-all">{scan.input || 'N/A'}</p>
                        </div>

                        {scan.duration && (
                            <div className="bg-green-50 rounded-xl p-4 text-center">
                                <p className="text-sm text-gray-600 mb-1 flex items-center justify-center gap-1">
                                    <Clock className="size-4" />
                                    Duration
                                </p>
                                <p className="font-semibold text-gray-900">{formatDuration(scan.duration)}</p>
                            </div>
                        )}
                    </div>

                    {/* Overall Accuracy - NEW */}
                    {scan.status === "completed" && scan.reportStats && (
                        <div className="bg-gradient-to-br from-blue-50 to-purple-50 rounded-xl p-6 mb-6">
                            <div className="flex items-center justify-between">
                                <div className="flex-1">
                                    <h3 className="text-lg font-semibold text-gray-900 mb-2">Overall Code Quality</h3>
                                    <p className="text-sm text-gray-600 mb-3">
                                        Based on {scan.reportStats.overallSeverityBreakdown?.ERROR || 0} critical errors across all files
                                    </p>
                                    <div className="flex gap-4 text-sm">
                                        <span className="text-red-600 font-medium">
                                            ⚠ {scan.reportStats.overallSeverityBreakdown?.ERROR || 0} Errors
                                        </span>
                                        <span className="text-yellow-600 font-medium">
                                            ⚡ {scan.reportStats.overallSeverityBreakdown?.WARNING || 0} Warnings
                                        </span>
                                        <span className="text-blue-600 font-medium">
                                            ℹ {scan.reportStats.overallSeverityBreakdown?.INFO || 0} Info
                                        </span>
                                    </div>
                                </div>

                                {/* Overall Accuracy Meter */}
                                <div className="relative w-32 h-32">
                                    <svg className="w-32 h-32 transform -rotate-90">
                                        <circle
                                            cx="64"
                                            cy="64"
                                            r="56"
                                            stroke="currentColor"
                                            strokeWidth="8"
                                            fill="none"
                                            className="text-gray-200"
                                        />
                                        <circle
                                            cx="64"
                                            cy="64"
                                            r="56"
                                            stroke="currentColor"
                                            strokeWidth="8"
                                            fill="none"
                                            className={
                                                scan.reportStats.overallColor === 'green' ? 'stroke-green-600' :
                                                    scan.reportStats.overallColor === 'yellow' ? 'stroke-yellow-600' :
                                                        scan.reportStats.overallColor === 'orange' ? 'stroke-orange-600' :
                                                            'stroke-red-600'
                                            }
                                            strokeDasharray={2 * Math.PI * 56}
                                            strokeDashoffset={2 * Math.PI * 56 - ((scan.reportStats.overallAccuracy || 0) / 100) * 2 * Math.PI * 56}
                                            strokeLinecap="round"
                                        />
                                    </svg>
                                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                                        <span className="text-3xl font-bold text-gray-900">
                                            {scan.reportStats.overallAccuracy || 0}%
                                        </span>
                                        <span className={`text-sm font-semibold ${scan.reportStats.overallColor === 'green' ? 'text-green-700' :
                                            scan.reportStats.overallColor === 'yellow' ? 'text-yellow-700' :
                                                scan.reportStats.overallColor === 'orange' ? 'text-orange-700' :
                                                    'text-red-700'
                                            }`}>
                                            {scan.reportStats.overallQuality || 'Unknown'}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Progress Bar */}
                    {scan.status === "completed" ? (
                        <div className="space-y-2">
                            <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
                                <div className="h-full bg-green-600 rounded-full" style={{ width: "100%" }} />
                            </div>
                            <p className="text-center text-sm text-gray-600">100% done</p>
                        </div>
                    ) : scan.status === "failed" ? (
                        <div className="space-y-2">
                            <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
                                <div className="h-full bg-red-600 rounded-full" style={{ width: "100%" }} />
                            </div>
                            <p className="text-center text-sm text-red-600">Failed</p>
                        </div>
                    ) : (
                        <div className="space-y-2">
                            <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
                                <div className="h-full bg-blue-600 rounded-full animate-pulse" style={{ width: "70%" }} />
                            </div>
                            <p className="text-center text-sm text-gray-600">Processing...</p>
                        </div>
                    )}
                </div>

                {/* Reports List with Accuracy Meters */}
                {scan.status === "completed" && scan.reportPaths && scan.reportPaths.length > 0 && (
                    <div className="bg-white border rounded-2xl shadow-sm p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-semibold text-gray-900">
                                Generated Reports ({scan.reportPaths.length})
                            </h3>
                            <FileSpreadsheet className="size-6 text-blue-600" />
                        </div>

                        <div className="space-y-3">
                            {scan.reportPaths.map((reportPath, index) => {
                                const filename = reportPath.split('/').pop() || `Report ${index + 1}`;
                                const language = filename.replace('_Review.xlsx', '').replace('.xlsx', '');

                                // Get report stats from backend
                                const stats = scan.reportStats?.reports?.[index] || {
                                    totalFindings: 0,
                                    severityBreakdown: { ERROR: 0, WARNING: 0, INFO: 0 }
                                };

                                return (
                                    <div
                                        key={index}
                                        className="border border-gray-200 rounded-xl p-4 hover:bg-gray-50 transition"
                                    >
                                        <div className="flex items-center justify-between gap-4">
                                            {/* File Info */}
                                            <div className="flex items-center gap-4 flex-1">
                                                <div className="w-12 h-12 rounded-lg bg-blue-100 flex items-center justify-center">
                                                    <FileSpreadsheet className="size-6 text-blue-700" />
                                                </div>

                                                <div className="flex-1">
                                                    <p className="font-semibold text-gray-900">{language}</p>
                                                    <p className="text-sm text-gray-500">{filename}</p>

                                                    {/* Severity Breakdown */}
                                                    <div className="flex gap-3 mt-1 text-xs">
                                                        {stats.severityBreakdown.ERROR > 0 && (
                                                            <span className="text-red-600 font-medium">
                                                                ⚠ {stats.severityBreakdown.ERROR} Errors
                                                            </span>
                                                        )}
                                                        {stats.severityBreakdown.WARNING > 0 && (
                                                            <span className="text-yellow-600 font-medium">
                                                                ⚡ {stats.severityBreakdown.WARNING} Warnings
                                                            </span>
                                                        )}
                                                        {stats.severityBreakdown.INFO > 0 && (
                                                            <span className="text-blue-600 font-medium">
                                                                ℹ {stats.severityBreakdown.INFO} Info
                                                            </span>
                                                        )}
                                                        {stats.totalFindings === 0 && (
                                                            <span className="text-green-600 font-medium">
                                                                ✓ No issues found
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Download Button */}
                                            <button
                                                onClick={() => handleDownloadReport(reportPath, index)}
                                                disabled={downloadingIndex === index}
                                                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
                                            >
                                                {downloadingIndex === index ? (
                                                    <>
                                                        <Loader2 className="size-4 animate-spin" />
                                                        Downloading...
                                                    </>
                                                ) : (
                                                    <>
                                                        <Download className="size-4" />
                                                        Download
                                                    </>
                                                )}
                                            </button>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}

                {/* Footer */}
                <div className="mt-6 text-center text-sm text-gray-500">
                    Rules applied: Semgrep YML rules + Extension-based scanning + Report generation
                </div>
            </div>
        </div>
    );
}
