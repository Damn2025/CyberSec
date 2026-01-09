import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import Navbar from "@/react-app/landing/components/Navbar";
import Hero from "@/react-app/landing/components/Hero";
import TrustedBy from "@/react-app/landing/components/TrustedBy";
import Advertisements from "@/react-app/landing/components/Advertisements";
import Features from "@/react-app/landing/components/Features";
import DetailedFeatures from "@/react-app/landing/components/DetailedFeatures";
import ScannerRoadmap from "@/react-app/landing/components/ScannerRoadmap";
import AboutSection from "@/react-app/landing/components/AboutSection";
import Testimonials from "@/react-app/landing/components/Testimonials";
import Pricing from "@/react-app/landing/components/Pricing";
import ContactUs from "@/react-app/landing/components/ContactUs";
import Footer from "@/react-app/landing/components/Footer";
import LoginModal from "@/react-app/landing/components/LoginModal";
import SignupModal from "@/react-app/landing/components/SignupModal";
import TrialScanModal from "@/react-app/components/TrialScanModal";
import TrialScanResults from "@/react-app/components/TrialScanResults";

import FloatingActions from "@/react-app/landing/components/FloatingActions";
import { useAuth } from "@/react-app/auth/AuthProvider";


export default function LandingPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [isLoginOpen, setIsLoginOpen] = useState(false);
  const [isSignupOpen, setIsSignupOpen] = useState(false);
  const [isTrialScanOpen, setIsTrialScanOpen] = useState(false);
  const [trialScanResults, setTrialScanResults] = useState<{
    scanType: 'web' | 'mobile';
    scan: any;
    vulnerabilities: any[];
  } | null>(null);

  useEffect(() => {
    if (user) navigate("/dashboard", { replace: true });
  }, [navigate, user]);

  const handleOpenLogin = () => {
    setIsSignupOpen(false);
    setIsLoginOpen(true);
  };

  const handleOpenSignup = () => {
    setIsLoginOpen(false);
    setIsSignupOpen(true);
  };

  const handleCloseLogin = () => setIsLoginOpen(false);
  const handleCloseSignup = () => setIsSignupOpen(false);

  const handleAuthed = () => {
    setIsLoginOpen(false);
    setIsSignupOpen(false);
    setIsTrialScanOpen(false);
    setTrialScanResults(null);
    navigate("/dashboard");
  };

  const handleTrialScanComplete = (scanType: 'web' | 'mobile', data: any) => {
    const trialScanData = {
      scanType,
      scan: data.scan || data,
      vulnerabilities: data.vulnerabilities || [],
      timestamp: Date.now(),
    };
    
    // Store in localStorage for later saving after signup/login
    localStorage.setItem('pendingTrialScan', JSON.stringify(trialScanData));
    
    setTrialScanResults({
      scanType,
      scan: data.scan || data,
      vulnerabilities: data.vulnerabilities || [],
    });
    setIsTrialScanOpen(false);
  };

  return (
    <div className="bg-black min-h-screen text-slate-200 selection:bg-red-500/30 selection:text-red-200">
      <Navbar onOpenLogin={handleOpenLogin} onOpenSignup={handleOpenSignup} />
      <Hero onOpenTrialScan={() => setIsTrialScanOpen(true)} />
      <AboutSection />
      <TrustedBy />
      <Features />
      <DetailedFeatures />
      <Testimonials />
      <ScannerRoadmap onOpenTrialScan={() => setIsTrialScanOpen(true)} />
      <Pricing onOpenSignup={handleOpenSignup} />
      <Advertisements />
      <ContactUs />
      <Footer />

      <LoginModal
        isOpen={isLoginOpen}
        onClose={handleCloseLogin}
        onSwitchToSignup={handleOpenSignup}
        onAuthenticated={handleAuthed}
      />
      <SignupModal
        isOpen={isSignupOpen}
        onClose={handleCloseSignup}
        onSwitchToLogin={handleOpenLogin}
        onAuthenticated={handleAuthed}
      />

      <TrialScanModal
        isOpen={isTrialScanOpen}
        onClose={() => setIsTrialScanOpen(false)}
        onScanComplete={handleTrialScanComplete}
        onOpenLogin={handleOpenLogin}
        onOpenSignup={handleOpenSignup}
      />

      {trialScanResults && (
        <TrialScanResults
          scanType={trialScanResults.scanType}
          scan={trialScanResults.scan}
          vulnerabilities={trialScanResults.vulnerabilities}
          onClose={() => setTrialScanResults(null)}
          onOpenLogin={handleOpenLogin}
          onOpenSignup={handleOpenSignup}
        />
      )}

      <FloatingActions />
    
    </div>
  );
}




