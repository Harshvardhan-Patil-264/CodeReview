import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
    Upload,
    Link2,
    ArrowLeft,
} from "lucide-react";
import { scanAPI } from "../../services/api";

export default function UploadProjectPage() {
    const navigate = useNavigate();

    const [method, setMethod] = useState("none");

    const [repoUrl, setRepoUrl] = useState("");
    const [zipFile, setZipFile] = useState(null);
    const [zipFileName, setZipFileName] = useState("");
    const [isUploading, setIsUploading] = useState(false);
    const [error, setError] = useState(null);

    const isScanEnabled = useMemo(() => {
        if (method === "zip") return zipFile !== null;
        if (method === "repo") return repoUrl.trim().length > 0;
        return false;
    }, [method, zipFile, repoUrl]);

    const handleFileSelect = (event) => {
        const file = event.target.files?.[0];
        if (file) {
            if (!file.name.endsWith('.zip')) {
                setError('Please select a ZIP file');
                return;
            }
            setZipFile(file);
            setZipFileName(file.name);
            setError(null);
        }
    };

    const handleStartScan = async () => {
        if (!isScanEnabled || isUploading) return;

        setIsUploading(true);
        setError(null);

        try {
            const formData = new FormData();

            if (method === "zip" && zipFile) {
                formData.append('type', 'upload');
                formData.append('file', zipFile);
            } else if (method === "repo") {
                formData.append('type', 'github');
                formData.append('url', repoUrl);
            }

            const response = await scanAPI.createScan(formData);

            if (response.success) {
                // Navigate to scan progress page with the scan ID
                navigate(`/scan-progress?scanId=${response.scanId}`);
            }
        } catch (err) {
            console.error('Scan creation failed:', err);
            setError(err.response?.data?.error?.message || 'Failed to start scan. Please try again.');
            setIsUploading(false);
        }
    };

    const resetToOptions = () => {
        setMethod("none");
        setRepoUrl("");
        setZipFile(null);
        setZipFileName("");
        setError(null);
    };

    return (
        <div className="bg-white px-6 py-10">
            <div className="max-w-4xl mx-auto">
                {/* Title */}
                <div className="text-center">
                    <h2 className="text-4xl font-bold text-gray-900">
                        Upload Project for Code Review
                    </h2>
                    <p className="text-gray-500 mt-2">
                        Upload your project folder to analyze code integrity and compliance
                    </p>
                </div>

                {/* Main Card */}
                <div className="mt-10 border rounded-2xl bg-white shadow-sm p-10">
                    {/* ✅ Before selecting (Screen 1) */}
                    {method === "none" && (
                        <>
                            <h3 className="text-center text-lg font-semibold text-gray-900 mb-8">
                                Select Upload Method
                            </h3>

                            <div className="space-y-6 max-w-2xl mx-auto">
                                {/* Option 1: Zip */}
                                <button
                                    className="w-full border rounded-2xl p-6 flex items-center gap-5 text-left hover:bg-blue-50 transition"
                                    onClick={() => setMethod("zip")}
                                >
                                    <div className="w-14 h-14 rounded-full bg-blue-50 flex items-center justify-center">
                                        <Upload className="size-6 text-blue-700" />
                                    </div>

                                    <div>
                                        <h4 className="text-lg font-semibold text-gray-900">
                                            Upload Zip File
                                        </h4>
                                        <p className="text-sm text-gray-500 mt-1">
                                            Upload a .zip file from your computer
                                        </p>
                                    </div>
                                </button>

                                {/* Option 2: Repo URL */}
                                <button
                                    className="w-full border rounded-2xl p-6 flex items-center gap-5 text-left hover:bg-gray-50 transition"
                                    onClick={() => setMethod("repo")}
                                >
                                    <div className="w-14 h-14 rounded-full bg-blue-50 flex items-center justify-center">
                                        <Link2 className="size-6 text-blue-700" />
                                    </div>

                                    <div>
                                        <h4 className="text-lg font-semibold text-gray-900">
                                            Enter Repository Path
                                        </h4>
                                        <p className="text-sm text-gray-500 mt-1">
                                            Provide a Git repository URL
                                        </p>
                                    </div>
                                </button>
                            </div>
                        </>
                    )}

                    {/* ✅ After selecting (Screen 2) */}
                    {method !== "none" && (
                        <>
                            <button
                                className="text-blue-600 hover:underline text-sm flex items-center gap-2"
                                onClick={resetToOptions}
                            >
                                <ArrowLeft className="size-4" />
                                Back to options
                            </button>

                            <div className="mt-6 max-w-2xl mx-auto">
                                {/* Zip UI */}
                                {method === "zip" && (
                                    <>
                                        <h3 className="text-lg font-semibold text-gray-900">
                                            Upload Zip File
                                        </h3>

                                        <div className="mt-4 border rounded-2xl p-6">
                                            <div className="border-2 border-dashed border-blue-300 rounded-2xl bg-blue-50 p-10 flex flex-col items-center justify-center text-center">
                                                <Upload className="size-12 text-gray-400" />
                                                <p className="mt-4 text-lg font-semibold text-gray-700">
                                                    Upload Zip File
                                                </p>

                                                <label className="mt-6 px-4 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 cursor-pointer">
                                                    Select Zip File
                                                    <input
                                                        type="file"
                                                        accept=".zip"
                                                        onChange={handleFileSelect}
                                                        className="hidden"
                                                    />
                                                </label>

                                                {zipFileName && (
                                                    <p className="mt-4 text-sm text-gray-700">
                                                        Selected:{" "}
                                                        <span className="font-semibold">{zipFileName}</span>
                                                    </p>
                                                )}
                                            </div>
                                        </div>
                                    </>
                                )}

                                {/* Repo UI */}
                                {method === "repo" && (
                                    <>
                                        <h3 className="text-lg font-semibold text-gray-900">
                                            Enter Repository Path
                                        </h3>

                                        <div className="mt-4 border rounded-2xl p-6 flex items-center gap-4">
                                            <div className="w-12 h-12 rounded-full bg-blue-50 flex items-center justify-center">
                                                <Link2 className="size-6 text-gray-400" />
                                            </div>

                                            <input
                                                value={repoUrl}
                                                onChange={(e) => setRepoUrl(e.target.value)}
                                                className="flex-1 border rounded-xl px-4 py-3 outline-none focus:ring-2 focus:ring-blue-300"
                                                placeholder="https://github.com/username/repository"
                                            />
                                        </div>
                                    </>
                                )}

                                {/* Error Message */}
                                {error && (
                                    <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm">
                                        {error}
                                    </div>
                                )}

                                {/* Start Scan Button */}
                                <button
                                    onClick={handleStartScan}
                                    disabled={!isScanEnabled || isUploading}
                                    className={`mt-8 w-full py-4 rounded-2xl font-semibold transition flex items-center justify-center gap-2 ${isScanEnabled && !isUploading
                                        ? "bg-blue-600 text-white hover:bg-blue-700"
                                        : "bg-gray-200 text-gray-500 cursor-not-allowed"
                                        }`}
                                >
                                    {!isUploading ? "Start Code Scan" : "Scanning..."}
                                </button>

                                {/* Indeterminate Progress Bar */}
                                {isUploading && (
                                    <div className="mt-6">
                                        <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
                                            <div className="h-full bg-gradient-to-r from-blue-400 via-blue-600 to-blue-400 animate-pulse"
                                                style={{
                                                    width: '100%',
                                                    animation: 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite'
                                                }}
                                            />
                                        </div>
                                        <p className="text-center text-sm text-gray-600 mt-2">
                                            Analyzing your code, please wait...
                                        </p>
                                    </div>
                                )}

                                <p className="text-center text-sm text-gray-500 mt-4">
                                    The system will automatically organize files by language and apply predefined rules.
                                </p>
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}
