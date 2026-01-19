import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
    LayoutDashboard,
    Upload,
    History,
    FileText,
    User,
    LogOut,
    PencilLine,
    Info,
    RefreshCw,
} from "lucide-react";

export default function AppLayout({ children }) {
    const navigate = useNavigate();
    const location = useLocation();
    const { user, logout } = useAuth();
    const [isRefreshing, setIsRefreshing] = useState(false);

    // Function to trigger refresh on dashboard
    const handleRefresh = () => {
        // Dispatch custom event that DashboardPage will listen to
        window.dispatchEvent(new CustomEvent('dashboardRefresh'));
    };

    // Listen for refresh state changes from dashboard
    useEffect(() => {
        const handleRefreshStart = () => setIsRefreshing(true);
        const handleRefreshEnd = () => setIsRefreshing(false);

        window.addEventListener('dashboardRefreshStart', handleRefreshStart);
        window.addEventListener('dashboardRefreshEnd', handleRefreshEnd);

        return () => {
            window.removeEventListener('dashboardRefreshStart', handleRefreshStart);
            window.removeEventListener('dashboardRefreshEnd', handleRefreshEnd);
        };
    }, []);

    const handleLogout = () => {
        logout();
        navigate("/login");
    };

    // Determine active route
    const isActive = (path) => location.pathname === path;

    const menuItems = [
        {
            path: "/dashboard",
            icon: LayoutDashboard,
            label: "Dashboard",
        },
        {
            path: "/upload",
            icon: Upload,
            label: "Upload Project",
        },
        {
            path: "/scan-history",
            icon: History,
            label: "Scan History",
        },
        {
            path: "/rule-generator",
            icon: PencilLine,
            label: "Rule Generator",
        },
        {
            path: "/profile",
            icon: User,
            label: "Profile",
        },
        {
            path: "/about",
            icon: Info,
            label: "About Project",
        },
    ];

    return (
        <div className="min-h-screen bg-white flex">
            {/* Static Sidebar */}
            <aside className="w-[260px] border-r bg-white px-4 py-6 flex flex-col fixed h-screen">
                <h2 className="text-lg font-semibold text-gray-900 mb-6">Menu</h2>

                <div className="space-y-2 flex-1">
                    {menuItems.map((item) => {
                        const Icon = item.icon;
                        const active = isActive(item.path);

                        return (
                            <button
                                key={item.path}
                                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition ${active
                                    ? "bg-blue-50 text-blue-700 font-medium"
                                    : "text-gray-700 hover:bg-gray-100"
                                    }`}
                                onClick={() => navigate(item.path)}
                            >
                                <Icon className="size-5" />
                                {item.label}
                            </button>
                        );
                    })}
                </div>

                {/* Logout Button at Bottom */}
                <div className="mt-4 pt-4 border-t">
                    <button
                        className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-gray-700 hover:bg-gray-100 transition"
                        onClick={handleLogout}
                    >
                        <LogOut className="size-5" />
                        Logout
                    </button>
                </div>
            </aside>

            {/* Main Content Area */}
            <div className="flex-1 ml-[260px]">
                {/* Static Top Header */}
                <header className="h-16 border-b flex items-center justify-between px-8 bg-white sticky top-0 z-10">
                    <div>
                        <h1 className="text-lg font-semibold text-gray-900">
                            Automating Code Integrity and Compliance
                        </h1>
                        <p className="text-xs text-gray-500">
                            Welcome, {user?.username || user?.email || "User"}
                        </p>
                    </div>

                    <div className="flex items-center gap-3">
                        {/* Refresh Button - Only shown on dashboard page */}
                        {location.pathname === '/dashboard' && (
                            <button
                                className="w-10 h-10 rounded-full bg-gray-50 flex items-center justify-center hover:bg-gray-100 transition disabled:opacity-50"
                                onClick={handleRefresh}
                                disabled={isRefreshing}
                                title="Refresh"
                            >
                                <RefreshCw className={`size-5 text-gray-700 ${isRefreshing ? 'animate-spin' : ''}`} />
                            </button>
                        )}

                        {/* Profile Button */}
                        <button
                            className="w-10 h-10 rounded-full bg-blue-50 flex items-center justify-center hover:bg-blue-100 transition"
                            onClick={() => navigate("/profile")}
                            title="Profile"
                        >
                            <User className="size-5 text-blue-700" />
                        </button>
                    </div>
                </header>

                {/* Page Content */}
                <main className="bg-white">
                    {children}
                </main>
            </div>
        </div>
    );
}
