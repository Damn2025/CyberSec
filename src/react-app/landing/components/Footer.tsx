import { Instagram, Linkedin } from 'lucide-react';
import Logo from '../assets/Cybersec.png';

const Footer = () => (
  <footer className="bg-black border-t border-white/10 py-8">
    <div className="container mx-auto px-6">
      <div className="flex flex-col md:flex-row justify-between items-center gap-4 text-gray-500 text-sm font-mono">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <img src={Logo} alt="CyberSec Logo" className="w-6 h-6" />
            <span className="text-white font-bold">
              CYBER<span className="text-red-600">SEC</span>
            </span>
          </div>
          <p className="hidden lg:block text-gray-500 text-xs max-w-xs">
            Next-generation cybersecurity scanning infrastructure designed for the modern web.
          </p>
        </div>
        <div className="flex items-center gap-6">
          <p>
            © {new Date().getFullYear()} {' '}
            <span className="text-yellow-500 font-semibold">EVOKE AI</span>. All rights reserved.
          </p>
          <a href="/privacy-policy" className="hover:text-red-500 transition-colors">
            Privacy Policy
          </a>
        </div>
        <div className="flex items-center gap-4">
          <a
            href="https://www.linkedin.com/company/ai-evoke/?viewAsMember=true"
            target="_blank"
            rel="noreferrer"
            aria-label="LinkedIn"
            title="LinkedIn"
            className="text-gray-500 hover:text-red-500 transition-colors"
          >
            <Linkedin className="w-5 h-5" />
          </a>
          <a
            href="http://www.instagram.com/ai_evoke?igsh=N2o4NXlvY2Q4emc1"
            target="_blank"
            rel="noreferrer"
            aria-label="Instagram"
            title="Instagram"
            className="text-gray-500 hover:text-red-500 transition-colors"
          >
            <Instagram className="w-5 h-5" />
          </a>
        </div>
      </div>
    </div>
  </footer>
);

export default Footer;





