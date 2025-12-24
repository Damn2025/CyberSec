import { BrowserRouter as Router, Routes, Route } from "react-router";
import Dashboard from "@/react-app/pages/Dashboard";
import ScanDetails from "@/react-app/pages/ScanDetails";
import MobileScanDetails from "@/react-app/pages/MobileScanDetails";
import LandingPage from "@/react-app/landing/LandingPage";
import { RequireAuth } from "@/react-app/auth/RequireAuth";
import PrivacyPolicy from "@/react-app/auth/PrivacyPolicy";


import { useEffect } from "react";

export default function App() {
  useEffect(() => {
    const handleContextMenu = (e: MouseEvent) => {
      e.preventDefault();
    };
    document.addEventListener("contextmenu", handleContextMenu);
    return () => {
      document.removeEventListener("contextmenu", handleContextMenu);
    };
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route
          path="/dashboard"
          element={
            <RequireAuth>
              <Dashboard />
            </RequireAuth>
          }
        />
        <Route
          path="/scans/:id"
          element={
            <RequireAuth>
              <ScanDetails />
            </RequireAuth>
          }
        />
        <Route
          path="/mobile-scans/:id"
          element={
            <RequireAuth>
              <MobileScanDetails />
            </RequireAuth>
          }
        />
        <Route
          path="/privacy-policy"
          element={<PrivacyPolicy />}
        />
      </Routes>
    </Router>
  );
}
