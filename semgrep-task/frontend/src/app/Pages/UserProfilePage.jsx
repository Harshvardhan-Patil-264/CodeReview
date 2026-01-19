import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/app/components/ui/card";
import { Button } from "@/app/components/ui/button";
import { ArrowLeft, Mail, User, Calendar, Shield, Github, Chrome, LogOut, Activity } from "lucide-react";
import { authAPI, scanAPI } from "../../services/api";

export default function UserProfilePage() {
    const navigate = useNavigate();

    const [user, setUser] = useState(null);
    const [scanStats, setScanStats] = useState({ total: 0, successful: 0 });
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        fetchUserData();
    }, []);

    const fetchUserData = async () => {
        try {
            setIsLoading(true);

            // Get user from localStorage or fetch from API
            const storedUser = authAPI.getStoredUser();
            if (storedUser) {
                setUser(storedUser);
            } else {
                // If not in localStorage, fetch from API
                const response = await authAPI.getCurrentUser();
                setUser(response.user);
            }

            // Fetch scan statistics
            try {
                const scansResponse = await scanAPI.getAllScans();
                const scans = scansResponse.scans || [];
                setScanStats({
                    total: scans.length,
                    successful: scans.filter(s => s.status === 'completed').length
                });
            } catch (scanError) {
                console.error("Could not fetch scan stats:", scanError);
            }

        } catch (err) {
            console.error("Error fetching user data:", err);
            setError("Failed to load user data");
            // If auth fails, redirect to login
            setTimeout(() => navigate('/login'), 2000);
        } finally {
            setIsLoading(false);
        }
    };

    const handleLogout = () => {
        authAPI.logout();
        navigate("/login");
    };

    const formatDate = (dateString) => {
        if (!dateString) return "N/A";
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    };

    const getProviderIcon = (provider) => {
        switch (provider) {
            case 'google':
                return <Chrome className="size-4 text-red-500" />;
            case 'github':
                return <Github className="size-4 text-gray-800" />;
            default:
                return <Shield className="size-4 text-blue-600" />;
        }
    };

    const getProviderLabel = (provider) => {
        switch (provider) {
            case 'google':
                return 'Google OAuth';
            case 'github':
                return 'GitHub OAuth';
            default:
                return 'Email/Password';
        }
    };

    if (isLoading) {
        return (
            <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                    <p className="text-gray-600">Loading profile...</p>
                </div>
            </div>
        );
    }

    if (error || !user) {
        return (
            <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <Card className="w-full max-w-md">
                    <CardContent className="pt-6">
                        <div className="text-center text-red-600 mb-4">{error || "User not found"}</div>
                        <Button className="w-full" onClick={() => navigate('/login')}>
                            Go to Login
                        </Button>
                    </CardContent>
                </Card>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-50 px-4 py-8">
            <div className="max-w-4xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                    <Button variant="outline" onClick={() => navigate("/dashboard")}>
                        <ArrowLeft className="mr-2 size-4" />
                        Dashboard
                    </Button>

                    <h1 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
                        <User className="size-5 text-blue-600" />
                        User Profile
                    </h1>

                    <div className="w-[110px]" />
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                    {/* Profile Information Card */}
                    <Card className="shadow-md">
                        <CardHeader>
                            <CardTitle className="text-xl">Profile Information</CardTitle>
                            <CardDescription>
                                Your account details and authentication information
                            </CardDescription>
                        </CardHeader>

                        <CardContent className="space-y-5">
                            {/* Username */}
                            <div className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                                <User className="size-5 text-blue-600 mt-0.5" />
                                <div className="flex-1">
                                    <p className="text-sm font-medium text-gray-500">Username</p>
                                    <p className="text-base font-semibold text-gray-900">{user.username}</p>
                                </div>
                            </div>

                            {/* Email */}
                            <div className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                                <Mail className="size-5 text-purple-600 mt-0.5" />
                                <div className="flex-1">
                                    <p className="text-sm font-medium text-gray-500">Email</p>
                                    <p className="text-base font-semibold text-gray-900">{user.email}</p>
                                </div>
                            </div>

                            {/* Account Created */}
                            <div className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                                <Calendar className="size-5 text-green-600 mt-0.5" />
                                <div className="flex-1">
                                    <p className="text-sm font-medium text-gray-500">Member Since</p>
                                    <p className="text-base font-semibold text-gray-900">
                                        {formatDate(user.createdAt)}
                                    </p>
                                </div>
                            </div>

                            {/* Auth Provider */}
                            <div className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                                {getProviderIcon(user.authProvider)}
                                <div className="flex-1">
                                    <p className="text-sm font-medium text-gray-500">Authentication Method</p>
                                    <p className="text-base font-semibold text-gray-900">
                                        {getProviderLabel(user.authProvider)}
                                    </p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    {/* Statistics Card */}
                    <div className="space-y-6">
                        <Card className="shadow-md">
                            <CardHeader>
                                <CardTitle className="text-xl">Account Statistics</CardTitle>
                                <CardDescription>
                                    Your activity and usage summary
                                </CardDescription>
                            </CardHeader>

                            <CardContent className="space-y-4">
                                {/* Total Scans */}
                                <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg border border-blue-200">
                                    <div className="flex items-center gap-3">
                                        <Activity className="size-6 text-blue-600" />
                                        <div>
                                            <p className="text-sm text-gray-600">Total Scans</p>
                                            <p className="text-2xl font-bold text-blue-600">{scanStats.total}</p>
                                        </div>
                                    </div>
                                </div>

                                {/* Successful Scans */}
                                <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg border border-green-200">
                                    <div className="flex items-center gap-3">
                                        <Activity className="size-6 text-green-600" />
                                        <div>
                                            <p className="text-sm text-gray-600">Successful Scans</p>
                                            <p className="text-2xl font-bold text-green-600">{scanStats.successful}</p>
                                        </div>
                                    </div>
                                </div>

                                {/* User ID */}
                                <div className="p-4 bg-gray-50 rounded-lg">
                                    <p className="text-xs font-medium text-gray-500 mb-1">User ID (UUID)</p>
                                    <code className="text-xs font-mono text-gray-700 bg-white px-2 py-1 rounded border break-all">
                                        {user.id}
                                    </code>
                                </div>
                            </CardContent>
                        </Card>

                        {/* Actions Card */}
                        <Card className="shadow-md">
                            <CardContent className="pt-6 space-y-3">
                                <Button
                                    variant="destructive"
                                    className="w-full"
                                    onClick={handleLogout}
                                >
                                    <LogOut className="mr-2 size-4" />
                                    Logout
                                </Button>
                            </CardContent>
                        </Card>
                    </div>
                </div>

                {/* Footer */}
                <div className="mt-6 text-center text-sm text-gray-500">
                    Your profile data is securely stored and encrypted in our database.
                </div>
            </div>
        </div>
    );
}
