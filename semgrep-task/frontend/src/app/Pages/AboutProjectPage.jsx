import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/app/components/ui/card";
import { Button } from "@/app/components/ui/button";
import {
    ArrowLeft,
    Code2,
    Database,
    FileSpreadsheet,
    SearchCheck,
    ShieldCheck,
} from "lucide-react";

export default function AboutProjectPage() {
    const navigate = useNavigate();

    return (
        <div className="min-h-screen bg-gray-50 px-4 py-8">
            <div className="max-w-4xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                    <Button variant="outline" onClick={() => navigate("/dashboard")}>
                        <ArrowLeft className="mr-2 size-4" />
                        Dashboard
                    </Button>

                    <h1 className="text-xl font-semibold text-gray-900">
                        About Project
                    </h1>

                    <div className="w-[90px]" />
                </div>

                {/* Main Card */}
                <Card className="shadow-md">
                    <CardHeader className="text-center space-y-2">
                        <CardTitle className="text-2xl">
                            Automating Code Integrity and Compliance
                        </CardTitle>
                        <CardDescription>
                            A web-based platform to review code quality and compliance for
                            multiple languages.
                        </CardDescription>
                    </CardHeader>

                    <CardContent className="space-y-6">
                        {/* What project does */}
                        <div className="space-y-2">
                            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                                <ShieldCheck className="size-5 text-blue-600" />
                                Project Purpose
                            </h2>
                            <p className="text-gray-700 text-sm leading-relaxed">
                                This platform helps users upload their project folder, scan
                                multiple programming languages (Java, JavaScript, Python, Go,
                                etc.), validate the code against standard rule sets (YML), and
                                generate a detailed compliance report.
                            </p>
                        </div>

                        {/* Technologies */}
                        <div className="space-y-3">
                            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                                <Code2 className="size-5 text-green-600" />
                                Technologies Used
                            </h2>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <Card className="bg-white border shadow-sm">
                                    <CardContent className="p-4 space-y-1">
                                        <h3 className="font-semibold text-gray-900">Frontend</h3>
                                        <p className="text-sm text-gray-600">React.js</p>
                                    </CardContent>
                                </Card>

                                <Card className="bg-white border shadow-sm">
                                    <CardContent className="p-4 space-y-1">
                                        <h3 className="font-semibold text-gray-900">Backend</h3>
                                        <p className="text-sm text-gray-600">Python + Node.js</p>
                                    </CardContent>
                                </Card>

                                <Card className="bg-white border shadow-sm">
                                    <CardContent className="p-4 space-y-1">
                                        <h3 className="font-semibold text-gray-900 flex items-center gap-2">
                                            <Database className="size-4 text-purple-600" />
                                            Database
                                        </h3>
                                        <p className="text-sm text-gray-600">MySQL</p>
                                    </CardContent>
                                </Card>

                                <Card className="bg-white border shadow-sm">
                                    <CardContent className="p-4 space-y-1">
                                        <h3 className="font-semibold text-gray-900">
                                            Tools / Libraries
                                        </h3>
                                        <p className="text-sm text-gray-600">
                                            Semgrep + Pandas + Excel API
                                        </p>
                                    </CardContent>
                                </Card>
                            </div>
                        </div>

                        {/* Flow */}
                        <div className="space-y-2">
                            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                                <SearchCheck className="size-5 text-orange-600" />
                                Project Flow
                            </h2>

                            <ol className="list-decimal ml-5 text-sm text-gray-700 space-y-1">
                                <li>User logs in / signs up.</li>
                                <li>User uploads the project folder.</li>
                                <li>Files are grouped by extension (.js, .py, .java, .go, etc.).</li>
                                <li>Rules (YML) are applied to review code compliance.</li>
                                <li>
                                    Output report is generated in Excel format and stored using
                                    Google Sheets API.
                                </li>
                                <li>Dashboard displays scan results, history and report links.</li>
                            </ol>
                        </div>

                        {/* Report section */}
                        <div className="space-y-2">
                            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                                <FileSpreadsheet className="size-5 text-emerald-600" />
                                Report Output
                            </h2>
                            <p className="text-gray-700 text-sm">
                                After scanning, a detailed Excel report is generated and shared
                                with the user, and the report link is stored in the database for
                                future access.
                            </p>
                        </div>

                        {/* Action */}
                        <div className="pt-2">
                            <Button className="w-full" onClick={() => navigate("/upload")}>
                                Start Scanning a Project
                            </Button>
                        </div>
                    </CardContent>
                </Card>

                {/* Footer */}
                <div className="mt-6 text-center text-sm text-gray-500">
                    You can check scans anytime from Dashboard → Scan History.
                </div>
            </div>
        </div>
    );
}
