import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/app/components/ui/card";
import { Input } from "@/app/components/ui/input";
import { Label } from "@/app/components/ui/label";
import { Button } from "@/app/components/ui/button";
import { User, Mail, Lock } from "lucide-react";
import { useAuth } from "../../context/AuthContext";

export default function SignupPage() {
    const navigate = useNavigate();
    const { register } = useAuth();

    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [error, setError] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    const handleSignup = async (e) => {
        e.preventDefault();
        setError("");
        setIsLoading(true);

        // Basic validation
        if (!username || !email || !password || !confirmPassword) {
            setError("Please fill in all fields");
            setIsLoading(false);
            return;
        }

        if (password !== confirmPassword) {
            setError("Passwords do not match");
            setIsLoading(false);
            return;
        }

        if (password.length < 6) {
            setError("Password must be at least 6 characters");
            setIsLoading(false);
            return;
        }

        try {
            // Use AuthContext register
            await register({ username, email, password });
            console.log("Registration successful");

            // Redirect to dashboard
            navigate("/dashboard");
        } catch (err) {
            console.error("Registration error:", err);
            setError(
                err.response?.data?.error?.message ||
                err.message ||
                "Registration failed. Please try again."
            );
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
            <Card className="w-full max-w-md shadow-lg">
                <CardHeader className="space-y-2 text-center pb-6">
                    <CardTitle className="text-3xl">Sign Up</CardTitle>
                    <CardDescription className="text-base">
                        Create your account to start code review
                    </CardDescription>
                </CardHeader>

                <CardContent>
                    <form onSubmit={handleSignup} className="space-y-5">
                        {/* Username */}
                        <div className="space-y-2">
                            <Label htmlFor="username" className="text-sm">
                                Username
                            </Label>
                            <div className="relative">
                                <User className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-gray-400" />
                                <Input
                                    id="username"
                                    type="text"
                                    placeholder="Choose a username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    className="pl-10"
                                    disabled={isLoading}
                                />
                            </div>
                        </div>

                        {/* Email */}
                        <div className="space-y-2">
                            <Label htmlFor="email" className="text-sm">
                                Email
                            </Label>
                            <div className="relative">
                                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-gray-400" />
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="Enter your email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    className="pl-10"
                                    disabled={isLoading}
                                />
                            </div>
                        </div>

                        {/* Password */}
                        <div className="space-y-2">
                            <Label htmlFor="password" className="text-sm">
                                Password
                            </Label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-gray-400" />
                                <Input
                                    id="password"
                                    type="password"
                                    placeholder="Create a password (min 6 characters)"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="pl-10"
                                    disabled={isLoading}
                                />
                            </div>
                        </div>

                        {/* Confirm Password */}
                        <div className="space-y-2">
                            <Label htmlFor="confirmPassword" className="text-sm">
                                Confirm Password
                            </Label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-gray-400" />
                                <Input
                                    id="confirmPassword"
                                    type="password"
                                    placeholder="Re-enter your password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    className="pl-10"
                                    disabled={isLoading}
                                />
                            </div>
                        </div>

                        {/* Error */}
                        {error && (
                            <div className="text-sm text-red-600 text-center py-1">
                                {error}
                            </div>
                        )}

                        {/* Sign Up Button */}
                        <Button
                            type="submit"
                            className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                            disabled={isLoading}
                        >
                            {isLoading ? "Creating Account..." : "Create Account"}
                        </Button>

                        {/* Login Link */}
                        <div className="text-center text-sm pt-4">
                            <span className="text-gray-600">Already have an account? </span>
                            <button
                                type="button"
                                className="text-blue-600 hover:text-blue-700 hover:underline"
                                onClick={() => navigate("/login")}
                            >
                                Login
                            </button>
                        </div>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
}
