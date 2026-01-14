import { useState, useEffect } from 'react';
import { MessageCircle, Phone, ArrowUp, Mail } from 'lucide-react';

const CONTACT = {
  email: 'vikaskaushalevoke.ai@gmail.com',
  phoneDisplay: '7986175240 ',
  phoneTel: '7986175240',
  whatsappNumber: '7986175240', // digits only for wa.me
};

const FloatingActions = () => {
  const [showScrollTop, setShowScrollTop] = useState(false);
  const whatsappText = encodeURIComponent('Hi CyberSec team — I have a question.');
  const whatsappHref = `https://wa.me/${CONTACT.whatsappNumber}?text=${whatsappText}`;

  useEffect(() => {
    const handleScroll = () => {
      // Show button when user scrolls down more than 300px
      setShowScrollTop(window.scrollY > 300);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  };

  const emailHref = `mailto:${CONTACT.email}`;

  return (
    <div className="fixed bottom-24 right-6 z-[55] flex flex-col gap-3">
      <a
        href={whatsappHref}
        target="_blank"
        rel="noreferrer"
        aria-label="Chat on WhatsApp"
        title="WhatsApp"
        className="group inline-flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500 text-white shadow-[0_0_20px_rgba(16,185,129,0.35)] transition-all hover:bg-emerald-600 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-emerald-400/60"
      >
        <MessageCircle className="h-5 w-5" />
      </a>

      <a
        href={emailHref}
        aria-label="Send us an email"
        title={`Email (${CONTACT.email})`}
        className="group inline-flex h-12 w-12 items-center justify-center rounded-full bg-red-600 text-white shadow-[0_0_20px_rgba(147,51,234,0.35)] transition-all hover:bg-purple-700 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-red-400/60"
      >
        <Mail className="h-5 w-5" />
      </a>

      <a
        href={`tel:${CONTACT.phoneTel}`}
        aria-label="Call us"
        title={`Call (${CONTACT.phoneDisplay})`}
        className="group inline-flex h-12 w-12 items-center justify-center rounded-full bg-sky-600 text-white shadow-[0_0_20px_rgba(2,132,199,0.35)] transition-all hover:bg-sky-700 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-sky-400/60"
      >
        <Phone className="h-5 w-5" />
      </a>

      {/* Scroll to Top Button */}
      <button
        onClick={scrollToTop}
        aria-label="Scroll to top"
        title="Scroll to top"
        className={`group inline-flex h-12 w-12 items-center justify-center rounded-full bg-red-600 text-white shadow-[0_0_20px_rgba(220,38,38,0.35)] transition-all duration-300 hover:bg-red-700 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-red-400/60 ${
          showScrollTop 
            ? 'opacity-100 translate-y-0 pointer-events-auto' 
            : 'opacity-0 translate-y-4 pointer-events-none'
        }`}
      >
        <ArrowUp className="h-5 w-5" />
      </button>
    </div>
  );
};

export default FloatingActions;



