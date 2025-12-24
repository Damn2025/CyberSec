import { useNavigate } from "react-router";

export default function PrivacyPolicy() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-black text-white px-6 py-10">
      <div className="max-w-4xl mx-auto bg-white text-black rounded-2xl shadow-lg p-8 relative">
        
        {/* Back Button */}
        <button
          onClick={() => navigate(-1)}
          className="mb-6 inline-flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition"
        >
          ← Go Back
        </button>

        <h1 className="text-3xl font-bold text-red-600 mb-2">
          Privacy Policy
        </h1>
        <p className="text-sm text-gray-600 mb-6">
          Last updated: December 20, 2025
        </p>

        <section className="space-y-6 text-sm leading-relaxed">
          <div>
            <h2 className="text-xl font-semibold text-black mb-2">
              Introduction
            </h2>
            <p>
              At <strong>EVOKE</strong>, we are committed to protecting your
              privacy. This Privacy Policy explains how we collect, use,
              disclose, and safeguard your information when you use our AI
              assistant service and website.
            </p>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              Information We Collect
            </h2>

            <h3 className="font-semibold mt-3">Personal Information</h3>
            <ul className="list-disc pl-5">
              <li>Register for an account</li>
              <li>Use our AI assistant services</li>
              <li>Contact us for support</li>
              <li>Subscribe to our newsletter</li>
              <li>Participate in surveys or promotions</li>
            </ul>
            <p className="mt-2">
              This may include your name, email address, phone number, company
              name, and any other information you choose to provide.
            </p>

            <h3 className="font-semibold mt-4">Usage Data</h3>
            <ul className="list-disc pl-5">
              <li>IP address and device information</li>
              <li>Browser type and version</li>
              <li>Pages visited and time spent</li>
              <li>Interactions with our AI assistant</li>
              <li>Date and time of access</li>
            </ul>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              How We Use Your Information
            </h2>
            <ul className="list-disc pl-5">
              <li>Provide and improve our services</li>
              <li>Manage accounts and transactions</li>
              <li>Customer support</li>
              <li>Send updates and marketing (with consent)</li>
              <li>Analyze usage trends</li>
              <li>Ensure security and compliance</li>
            </ul>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              Data Sharing and Disclosure
            </h2>
            <p>We do not sell your personal information.</p>
            <ul className="list-disc pl-5 mt-2">
              <li>Service providers</li>
              <li>Legal obligations</li>
              <li>Business transfers</li>
              <li>With your consent</li>
            </ul>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              Data Security
            </h2>
            <p>
              We use appropriate security measures to protect your data, but no
              online transmission is 100% secure.
            </p>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              Your Rights
            </h2>
            <ul className="list-disc pl-5">
              <li>Access your data</li>
              <li>Correct inaccuracies</li>
              <li>Request deletion</li>
              <li>Restrict or object to processing</li>
              <li>Data portability</li>
              <li>Withdraw consent</li>
            </ul>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              Cookies and Tracking
            </h2>
            <p>
              We use cookies to improve user experience. You can control cookies
              through your browser settings.
            </p>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              Children's Privacy
            </h2>
            <p>
              Our services are not intended for users under 18. We do not
              knowingly collect children's data.
            </p>
          </div>

          <div>
            <h2 className="text-xl font-semibold mb-2">
              Changes to This Policy
            </h2>
            <p>
              We may update this Privacy Policy periodically. Please review it
              regularly for changes.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}

