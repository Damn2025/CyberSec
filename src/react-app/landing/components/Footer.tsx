import { Instagram, Linkedin } from 'lucide-react';
import Logo from '../assets/Cybersec.png';

const Footer = () => (
  <footer className="bg-black border-t border-white/10 py-8">
    <div className="container mx-auto px-6">
      <div className="flex flex-col md:flex-row justify-between items-center gap-8 md:gap-4 text-gray-500 text-sm font-mono">
        {/* Brand Section */}
        <div className="flex flex-col sm:flex-row items-center gap-3 md:gap-4">
          <div className="flex items-center gap-2">
            <img src={Logo} alt="CyberSec Logo" className="w-6 h-6" />
            <span className="text-white font-bold text-base">
              CYBER<span className="text-red-600">SEC</span>
            </span>
          </div>
          <p className="hidden md:block w-px h-4 bg-gray-800"></p>
          <p className="text-gray-500 text-xs text-center sm:text-left max-w-[200px] sm:max-w-xs">
            Next-generation cybersecurity scanning infrastructure.
          </p>
        </div>

        {/* Links & Copyright */}
        <div className="flex flex-col-reverse sm:flex-row items-center gap-4 sm:gap-6 md:gap-8">
          <p className="text-center sm:text-left">
            © {new Date().getFullYear()} {' '}
            <span className="text-white hover:text-red-500 transition-colors cursor-pointer">EVOKE AI</span>
          </p>
          <a href="/privacy-policy" className="hover:text-red-500 transition-colors text-center">
            Privacy Policy
          </a>
        </div>

        {/* Social Icons */}
        <div className="flex items-center gap-4">
          <a
            href="https://www.linkedin.com/company/ai-evoke/?viewAsMember=true"
            target="_blank"
            rel="noreferrer"
            aria-label="LinkedIn"
            title="LinkedIn"
            className="p-2 bg-white/5 hover:bg-white/10 rounded-full text-gray-400 hover:text-white hover:scale-110 transition-all duration-300"
          >
            <Linkedin className="w-4 h-4" />
          </a>
          <a
            href="http://www.instagram.com/ai_evoke?igsh=N2o4NXlvY2Q4emc1"
            target="_blank"
            rel="noreferrer"
            aria-label="Instagram"
            title="Instagram"
            className="p-2 bg-white/5 hover:bg-white/10 rounded-full text-gray-400 hover:text-white hover:scale-110 transition-all duration-300"
          >
            <Instagram className="w-4 h-4" />
          </a>
        </div>
      </div>
    </div>
  </footer>
);

export default Footer;





