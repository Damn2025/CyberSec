import { useNavigate } from "react-router";
import Navbar from "@/react-app/landing/components/Navbar";
import Footer from "@/react-app/landing/components/Footer";

export default function PrivacyPolicy() {
  const navigate = useNavigate();

  const handleOpenLogin = () => {
    navigate("/");
  };

  const handleOpenSignup = () => {
    navigate("/");
  };

  return (
    <div className="bg-black min-h-screen text-slate-200 selection:bg-red-500/30 selection:text-red-200">
      <Navbar onOpenLogin={handleOpenLogin} onOpenSignup={handleOpenSignup} />
      
      <div className="pt-32 pb-20 px-6">
        <div className="container mx-auto max-w-4xl">
          {/* Back Button */}
          <button
            onClick={() => navigate(-1)}
            className="mb-8 inline-flex items-center gap-2 border border-red-600 text-red-500 px-6 py-2 hover:bg-red-600 hover:text-black transition-all duration-300 shadow-[0_0_10px_rgba(220,38,38,0.3)] hover:shadow-[0_0_20px_rgba(220,38,38,0.6)] font-mono text-sm tracking-widest uppercase"
          >
            ← Go Back
          </button>

          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4 font-mono tracking-tight">
            Privacy <span className="text-red-600">Policy</span>
          </h1>
          <p className="text-sm text-gray-400 mb-12 font-mono">
            Last updated: December 20, 2025
          </p>

          <section className="space-y-8 text-sm leading-relaxed text-gray-300">
            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Introduction
              </h2>
              <p className="text-gray-300">
                At <strong className="text-red-500">EVOKE</strong>, we are committed to protecting your
                privacy. This Privacy Policy explains how we collect, use,
                disclose, and safeguard your information when you use our AI
                assistant service and website.
              </p>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Information We Collect
              </h2>

              <h3 className="font-semibold mt-4 text-white mb-2">Personal Information</h3>
              <ul className="list-disc pl-6 space-y-2 text-gray-300">
                <li>Register for an account</li>
                <li>Use our AI assistant services</li>
                <li>Contact us for support</li>
                <li>Subscribe to our newsletter</li>
                <li>Participate in surveys or promotions</li>
              </ul>
              <p className="mt-4 text-gray-300">
                This may include your name, email address, phone number, company
                name, and any other information you choose to provide.
              </p>

              <h3 className="font-semibold mt-6 text-white mb-2">Usage Data</h3>
              <ul className="list-disc pl-6 space-y-2 text-gray-300">
                <li>IP address and device information</li>
                <li>Browser type and version</li>
                <li>Pages visited and time spent</li>
                <li>Interactions with our AI assistant</li>
                <li>Date and time of access</li>
              </ul>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                How We Use Your Information
              </h2>
              <ul className="list-disc pl-6 space-y-2 text-gray-300">
                <li>Provide and improve our services</li>
                <li>Manage accounts and transactions</li>
                <li>Customer support</li>
                <li>Send updates and marketing (with consent)</li>
                <li>Analyze usage trends</li>
                <li>Ensure security and compliance</li>
              </ul>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Data Sharing and Disclosure
              </h2>
              <p className="text-gray-300 mb-3">We do not sell your personal information.</p>
              <ul className="list-disc pl-6 space-y-2 text-gray-300">
                <li>Service providers</li>
                <li>Legal obligations</li>
                <li>Business transfers</li>
                <li>With your consent</li>
              </ul>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Data Security
              </h2>
              <p className="text-gray-300">
                We use appropriate security measures to protect your data, but no
                online transmission is 100% secure.
              </p>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Your Rights
              </h2>
              <ul className="list-disc pl-6 space-y-2 text-gray-300">
                <li>Access your data</li>
                <li>Correct inaccuracies</li>
                <li>Request deletion</li>
                <li>Restrict or object to processing</li>
                <li>Data portability</li>
                <li>Withdraw consent</li>
              </ul>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Cookies and Tracking
              </h2>
              <p className="text-gray-300">
                We use cookies to improve user experience. You can control cookies
                through your browser settings.
              </p>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Children's Privacy
              </h2>
              <p className="text-gray-300">
                Our services are not intended for users under 18. We do not
                knowingly collect children's data.
              </p>
            </div>

            <div>
              <h2 className="text-2xl font-semibold text-white mb-4 font-mono">
                Changes to This Policy
              </h2>
              <p className="text-gray-300">
                We may update this Privacy Policy periodically. Please review it
                regularly for changes.
              </p>
            </div>
          </section>
        </div>
      </div>

      <Footer />
    </div>
  );
}

