import { Mail, MessageCircle, Phone } from 'lucide-react';

const CONTACT = {
  email: 'vikaskaushalevoke.ai@gmail.com',
  phoneDisplay: '+1 (234) 567-890',
  phoneTel: '7986175240',
  whatsappNumber: '7986175240', // digits only for wa.me
};

const FloatingActions = () => {
  const whatsappText = encodeURIComponent('Hi CyberSec team — I have a question.');
  const whatsappHref = `https://wa.me/${CONTACT.whatsappNumber}?text=${whatsappText}`;

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
        href={`tel:${CONTACT.phoneTel}`}
        aria-label="Call us"
        title={`Call (${CONTACT.phoneDisplay})`}
        className="group inline-flex h-12 w-12 items-center justify-center rounded-full bg-sky-600 text-white shadow-[0_0_20px_rgba(2,132,199,0.35)] transition-all hover:bg-sky-700 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-sky-400/60"
      >
        <Phone className="h-5 w-5" />
      </a>

      <a
        href={`mailto:${CONTACT.email}`}
        aria-label="Email us"
        title={`Email (${CONTACT.email})`}
        className="group inline-flex h-12 w-12 items-center justify-center rounded-full bg-red-600 text-white shadow-[0_0_20px_rgba(220,38,38,0.35)] transition-all hover:bg-red-700 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-red-400/60"
      >
        <Mail className="h-5 w-5" />
      </a>
    </div>
  );
};

export default FloatingActions;



