import { BrowserRouter as Router, Routes, Route } from "react-router";
import Dashboard from "@/react-app/pages/Dashboard";
import ScanDetails from "@/react-app/pages/ScanDetails";
import MobileScanDetails from "@/react-app/pages/MobileScanDetails";

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans/:id" element={<ScanDetails />} />
        <Route path="/mobile-scans/:id" element={<MobileScanDetails />} />
      </Routes>
    </Router>
  );
}
