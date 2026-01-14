import { useState, useEffect } from 'react';
import { Menu, Moon, Sun, X } from 'lucide-react';
import cybersecLogo from '../assets/Cybersec.png';
import { useTheme } from '../hooks/useTheme';

type NavbarProps = {
  onOpenLogin: () => void;
  onOpenSignup: () => void;
};

const Navbar = ({ onOpenLogin, onOpenSignup }: NavbarProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const { isDark, toggleTheme } = useTheme();

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <nav className={`fixed w-full z-50 transition-all duration-300 border-b border-white/5 ${scrolled ? 'bg-black/90 backdrop-blur-md py-4' : 'bg-transparent py-6'}`}>
      <div className="container mx-auto px-6 flex justify-between items-center">
        <div className="flex items-center gap-2 text-white">
          <img src={cybersecLogo} alt="CyberSec Logo" className="h-10 w-auto" />
          <div className="leading-tight">
            <div className="text-2xl font-bold tracking-tight text-shadow-glow">
              CYBER<span className="text-red-600">SEC</span>
            </div>
            <div className="text-[10px] sm:text-xs font-mono tracking-[0.25em] uppercase text-gray-300 ml-1">
              A DIVISION OF <span className='text-cyan-500 font-semibold'>EVOKE AI</span>
            </div>
          </div>
        </div>
        
        {/* Desktop Menu */}
        <div className="hidden md:flex items-center gap-6 font-mono text-sm tracking-widest uppercase">
          <a href="#about" className="hover:text-red-500 transition-colors">About</a>
          <a href="#detailed-features" className="hover:text-red-500 transition-colors">Capabilities</a>
          {/* <a href="#scanner" className="hover:text-red-500 transition-colors">Scanner</a> */}
          <a href="#testimonials" className="hover:text-red-500 transition-colors">Testimonials</a>
          <a href="#pricing" className="hover:text-red-500 transition-colors">Pricing</a>
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            title={isDark ? 'Light mode' : 'Dark mode'}
            className="inline-flex items-center justify-center h-10 w-10 rounded border border-white/10 bg-black/50 hover:bg-black/70 transition-colors"
          >
            {isDark ? <Sun size={18} /> : <Moon size={18} />}
          </button>
     
          <button 
            onClick={onOpenLogin}
            className="border border-red-600 text-red-500 px-6 py-2 hover:bg-red-600 hover:text-black transition-all duration-300 shadow-[0_0_10px_rgba(220,38,38,0.3)] hover:shadow-[0_0_20px_rgba(220,38,38,0.6)]"
          >
            Login
          </button>
          <button 
            onClick={onOpenSignup}
            className="bg-red-600 text-white px-6 py-2 hover:bg-red-700 transition-all duration-300 shadow-[0_0_10px_rgba(220,38,38,0.3)] hover:shadow-[0_0_20px_rgba(220,38,38,0.6)]"
          >
            Sign Up
          </button>

          <a 
            href="#contact"
            className="border border-red-500 text-red-400 px-6 py-2 hover:bg-red-500 hover:text-black transition-all duration-300 shadow-[0_0_10px_rgba(6,182,212,0.3)] hover:shadow-[0_0_20px_rgba(6,182,212,0.6)]"
          >
            Get in Touch
          </a>
        </div>

       

        {/* Mobile Toggle */}
        <button className="md:hidden text-white" onClick={() => setIsOpen(!isOpen)}>
          {isOpen ? <X /> : <Menu />}
        </button>
         

      </div>

      {/* Mobile Menu */}
      {isOpen && (
        <div className="md:hidden absolute top-full left-0 w-full bg-black border-b border-red-900/30 p-6 flex flex-col gap-6 font-mono text-center">
          <a href="#threat-analyzer" onClick={() => setIsOpen(false)} className="text-gray-300 hover:text-red-500">AI Analysis</a>
          <a href="#features" onClick={() => setIsOpen(false)} className="text-gray-300 hover:text-red-500">Features</a>
          <a href="#roadmap" onClick={() => setIsOpen(false)} className="text-gray-300 hover:text-red-500">Roadmap</a>
          <a href="#testimonials" onClick={() => setIsOpen(false)} className="text-gray-300 hover:text-red-500">Testimonials</a>
          <a href="#pricing" onClick={() => setIsOpen(false)} className="text-gray-300 hover:text-red-500">Pricing</a>
          <a 
            href="#contact" 
            onClick={() => setIsOpen(false)} 
            className="border border-cyan-500 text-cyan-400 px-6 py-2 hover:bg-cyan-500 hover:text-black transition-all duration-300"
          >
            Get in Touch
          </a>
          <button
            type="button"
            onClick={() => {
              toggleTheme();
              setIsOpen(false);
            }}
            className="border border-white/10 bg-black/50 px-6 py-2 hover:bg-black/70 transition-colors"
          >
            {isDark ? 'Light Mode' : 'Dark Mode'}
          </button>
          <button 
            onClick={() => { setIsOpen(false); onOpenLogin(); }}
            className="border border-red-600 text-red-500 px-6 py-2 hover:bg-red-600 hover:text-black transition-all"
          >
            Login
          </button>
          <button 
            onClick={() => { setIsOpen(false); onOpenSignup(); }}
            className="bg-red-600 text-white px-6 py-2 hover:bg-red-700 transition-all"
          >
            Sign Up
          </button>
        </div>
      )}
    </nav>
  );
};

export default Navbar;



