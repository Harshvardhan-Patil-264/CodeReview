import { Routes, Route, Navigate } from "react-router-dom";
import ProtectedRoute from "../components/ProtectedRoute";
import AppLayout from "../components/AppLayout";

import LoginPage from "./Pages/LoginPage";
import SignupPage from "./Pages/SignupPage";
import DashboardPage from "./Pages/DashboardPage";
import UploadProjectPage from "./Pages/UploadProjectPage";
import ScanProgressPage from "./Pages/ScanProgressPage";
import ScanHistoryPage from "./Pages/ScanHistoryPage";
import RuleGeneratorPage from "./Pages/RuleGeneratorPage";
import UserProfilePage from "./Pages/UserProfilePage";
import AboutProjectPage from "./Pages/AboutProjectPage";

export default function App() {
  return (
    <Routes>
      {/* Default - redirect to dashboard */}
      <Route path="/" element={<Navigate to="/dashboard" replace />} />

      {/* Public Auth Routes */}
      <Route path="/login" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />

      {/* Protected Routes with Shared Layout */}
      <Route path="/*" element={
        <ProtectedRoute>
          <AppLayout>
            <Routes>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/upload" element={<UploadProjectPage />} />
              <Route path="/scan-progress" element={<ScanProgressPage />} />
              <Route path="/scan-history" element={<ScanHistoryPage />} />
              <Route path="/rule-generator" element={<RuleGeneratorPage />} />
              <Route path="/profile" element={<UserProfilePage />} />
              <Route path="/about" element={<AboutProjectPage />} />
            </Routes>
          </AppLayout>
        </ProtectedRoute>
      } />
    </Routes>
  );
}
