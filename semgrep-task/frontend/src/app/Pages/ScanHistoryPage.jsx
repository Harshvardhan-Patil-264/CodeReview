import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Download, Eye, History, Loader2, RefreshCw } from "lucide-react";
import { scanAPI } from "../../services/api";


export default function ScanHistoryPage() {
    const navigate = useNavigate();

    const [scans, setScans] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    // Load scans on component mount
    useEffect(() => {
        loadScans();
    }, []);

    const loadScans = async () => {
        setIsLoading(true);
        setError(null);
        try {
            const response = await scanAPI.getAllScans();
            if (response.success) {
                setScans(response.scans || []);
            }
        } catch (err) {
            console.error("Failed to load scans:", err);
            setError("Failed to load scan history");
        } finally {
            setIsLoading(false);
        }
    };

    const handleView = (scan) => {
        console.log("View scan details:", scan);
        // Navigate to scan progress page for details
        navigate(`/scan-progress?scanId=${scan.id}`);
    };

    const handleDownload = async (scan) => {
        if (!scan.reportPaths || scan.reportPaths.length === 0 || scan.status !== "completed") {
            alert("Report not available for this scan");
            return;
        }

        try {
            const blob = await scanAPI.downloadReport(scan.id);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `scan-${scan.id}-report.xlsx`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (err) {
            console.error("Failed to download report:", err);
            alert("Failed to download report");
        }
    };

    return (
        <div className="min-h-screen bg-gray-50 px-4 py-8">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                    <button
                        onClick={() => navigate("/dashboard")}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl border bg-white hover:bg-gray-50 transition"
                    >
                        <ArrowLeft className="size-4" />
                        Dashboard
                    </button>

                    <h1 className="text-2xl font-semibold text-gray-900 flex items-center gap-2">
                        <History className="size-6 text-purple-600" />
                        Scan History
                    </h1>

                    <button
                        onClick={loadScans}
                        disabled={isLoading}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl border bg-white hover:bg-gray-50 transition disabled:opacity-50"
                    >
                        <RefreshCw className={`size-4 ${isLoading ? "animate-spin" : ""}`} />
                        Refresh
                    </button>
                </div>

                {/* Error Message */}
                {error && (
                    <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700">
                        {error}
                    </div>
                )}

                {/* Loading State */}
                {isLoading ? (
                    <div className="py-20 text-center text-gray-500">
                        <Loader2 className="size-12 animate-spin mx-auto mb-4" />
                        <p>Loading scan history...</p>
                    </div>
                ) : scans.length === 0 ? (
                    <div className="py-20 text-center">
                        <History className="size-16 mx-auto text-gray-300 mb-4" />
                        <p className="text-gray-500 text-lg">No scans found</p>
                        <p className="text-gray-400 text-sm mt-2">
                            Upload a project to start your first code review
                        </p>
                        <button
                            onClick={() => navigate("/upload")}
                            className="mt-6 px-6 py-3 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition"
                        >
                            Upload Project
                        </button>
                    </div>
                ) : (
                    /* List */
                    <div className="space-y-4">
                        {scans.map((scan) => (
                            <div
                                key={scan.id}
                                className="bg-white border rounded-2xl shadow-sm p-6 hover:shadow-md transition"
                            >
                                <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                                    <div className="flex-1">
                                        <h3 className="text-lg font-semibold text-gray-900">
                                            Scan #{scan.id}
                                        </h3>
                                        <p className="text-sm text-gray-600 mt-1">
                                            Type: {scan.type?.toUpperCase() || 'N/A'} • Source: {scan.input || 'N/A'} •{" "}
                                            {new Date(scan.createdAt).toLocaleString()}
                                        </p>
                                        <div className="mt-2">
                                            <StatusBadge status={scan.status} />
                                        </div>
                                    </div>

                                    <div className="flex flex-col sm:flex-row gap-3">
                                        <button
                                            onClick={() => handleView(scan)}
                                            className="flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-blue-600 text-white hover:bg-blue-700 transition"
                                        >
                                            <Eye className="size-4" />
                                            View Details
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Footer */}
                <div className="mt-8 text-center text-sm text-gray-500">
                    {scans.length > 0 && `Showing ${scans.length} scan${scans.length > 1 ? "s" : ""}`}
                </div>
            </div>
        </div>
    );
}

function StatusBadge({ status }) {
    const getStatusStyles = () => {
        switch (status) {
            case "completed":
                return "bg-green-100 text-green-700 border-green-200";
            case "failed":
                return "bg-red-100 text-red-700 border-red-200";
            case "processing":
                return "bg-blue-100 text-blue-700 border-blue-200";
            case "pending":
                return "bg-yellow-100 text-yellow-700 border-yellow-200";
            default:
                return "bg-gray-100 text-gray-700 border-gray-200";
        }
    };

    return (
        <span className={`inline-flex px-3 py-1 rounded-full text-xs font-semibold border ${getStatusStyles()}`}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
    );
}
