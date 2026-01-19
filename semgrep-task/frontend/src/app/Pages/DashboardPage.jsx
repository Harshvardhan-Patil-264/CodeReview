import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
    TrendingUp,
    CheckCircle2,
    XCircle,
    Eye,
    Loader2,
    Clock,
} from "lucide-react";
import { scanAPI } from "../../services/api";
import { useAuth } from "../../context/AuthContext";


export default function DashboardPage() {
    const navigate = useNavigate();
    const { user } = useAuth();

    const [scans, setScans] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    // Load scans on component mount
    useEffect(() => {
        loadScans();
    }, []);

    // Listen for refresh event from header
    useEffect(() => {
        const handleRefresh = () => {
            loadScans();
        };

        window.addEventListener('dashboardRefresh', handleRefresh);

        return () => {
            window.removeEventListener('dashboardRefresh', handleRefresh);
        };
    }, []);

    const loadScans = async () => {
        setIsLoading(true);
        setError(null);
        // Notify header that refresh started
        window.dispatchEvent(new CustomEvent('dashboardRefreshStart'));
        try {
            const response = await scanAPI.getAllScans();
            if (response.success) {
                setScans(response.scans || []);
            }
        } catch (err) {
            console.error("Failed to load scans:", err);
            setError("Failed to load scan data");
        } finally {
            setIsLoading(false);
            // Notify header that refresh ended
            window.dispatchEvent(new CustomEvent('dashboardRefreshEnd'));
        }
    };

    const downloadReport = async (scanId) => {
        try {
            const blob = await scanAPI.downloadReport(scanId);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `scan-${scanId}-report.xlsx`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (err) {
            console.error("Failed to download report:", err);
            alert("Failed to download report");
        }
    };

    // Calculate statistics from scans
    const stats = {
        total: scans.length,
        completed: scans.filter((s) => s.status === "completed").length,
        failed: scans.filter((s) => s.status === "failed").length,
        pending: scans.filter((s) => s.status === "running" || s.status === "pending").length,
        lastScan: scans.length > 0 ? new Date(scans[0].createdAt).toLocaleDateString() : "N/A",
    };

    return (
        <div className="px-8 py-8">
            {/* Error Message */}
            {error && (
                <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700">
                    {error}
                </div>
            )}

            {/* Stats Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mt-8">
                <StatCard
                    title="Total Projects Scanned"
                    value={stats.total.toString()}
                    icon={<TrendingUp className="size-6 text-blue-700" />}
                    iconBg="bg-blue-50"
                />

                <StatCard
                    title="Successful Scans"
                    value={stats.completed.toString()}
                    icon={<CheckCircle2 className="size-6 text-green-700" />}
                    iconBg="bg-green-50"
                />

                <StatCard
                    title="Failed Scans"
                    value={stats.failed.toString()}
                    icon={<XCircle className="size-6 text-red-700" />}
                    iconBg="bg-red-50"
                />

                <StatCard
                    title="Pending Scans"
                    value={stats.pending.toString()}
                    icon={<Clock className="size-6 text-orange-700" />}
                    iconBg="bg-orange-50"
                />
            </div>

            {/* Recent Scan Activity */}
            <div className="mt-10 border rounded-2xl overflow-hidden bg-white">
                <div className="px-6 py-5 border-b">
                    <h2 className="text-lg font-semibold text-gray-900">
                        Recent Scan Activity
                    </h2>
                </div>

                {isLoading ? (
                    <div className="p-10 text-center text-gray-500">
                        <Loader2 className="size-8 animate-spin mx-auto mb-2" />
                        Loading scans...
                    </div>
                ) : scans.length === 0 ? (
                    <div className="p-10 text-center text-gray-500">
                        No scans found. Upload a project to get started!
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="text-left text-xs text-gray-500 uppercase tracking-wide border-b">
                                    <th className="px-6 py-4">Project Name</th>
                                    <th className="px-6 py-4">Project ID</th>
                                    <th className="px-6 py-4">Scan Date</th>
                                    <th className="px-6 py-4">Status</th>
                                    <th className="px-6 py-4">Actions</th>
                                </tr>
                            </thead>

                            <tbody>
                                {scans.slice(0, 10).map((scan) => (
                                    <tr
                                        key={scan.id}
                                        className="border-b last:border-b-0 hover:bg-gray-50 transition"
                                    >
                                        <td className="px-6 py-5 text-gray-900 font-medium">
                                            {scan.input || 'N/A'}
                                        </td>
                                        <td className="px-6 py-5 text-gray-700 text-sm">{scan.id}</td>
                                        <td className="px-6 py-5 text-gray-700">
                                            {new Date(scan.createdAt).toLocaleString()}
                                        </td>

                                        <td className="px-6 py-5">
                                            <StatusBadge status={scan.status} />
                                        </td>

                                        <td className="px-6 py-5">
                                            <button
                                                onClick={() => navigate(`/scan-progress?scanId=${scan.id}`)}
                                                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 text-white hover:bg-blue-700 transition text-sm font-medium"
                                            >
                                                <Eye className="size-4" />
                                                View Details
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Bottom spacing */}
            <div className="h-10" />
        </div>
    );
}

/* ----------------- Small UI Components ----------------- */

function StatCard({ title, value, icon, iconBg }) {
    return (
        <div className="border rounded-2xl bg-white p-6 flex items-center justify-between shadow-sm">
            <div>
                <p className="text-sm text-gray-600">{title}</p>
                <p className="text-4xl font-semibold text-gray-900 mt-3">{value}</p>
            </div>
            <div className={`w-14 h-14 rounded-2xl ${iconBg} flex items-center justify-center`}>
                {icon}
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
        <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${getStatusStyles()}`}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
    );
}
