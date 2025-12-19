import type { ChangeEvent, FormEvent } from "react";
import { useState } from 'react';
import emailjs from "@emailjs/browser";
import { Send, CheckCircle, AlertCircle } from 'lucide-react';

const ContactUs = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone:'',
    message: ''

  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<null | 'success' | 'error'>(null);

  const handleChange = (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitStatus(null);

    try {
      const serviceId = "service_qnt6t5y";
      const templateId = "template_rvorv0e";
      const publicKey = import.meta.env.VITE_EMAILJS_PUBLIC_KEY;

      if (!publicKey) {
        console.error("VITE_EMAILJS_PUBLIC_KEY is not set");
        throw new Error("Email service is not configured");
      }

      await emailjs.send(
        serviceId,
        templateId,
        {
          fullname: formData.name,
          email: formData.email,
          phone: formData.phone,
          message: formData.message,
        },
        publicKey,
      );

      setSubmitStatus("success");
      setFormData({ name: "", email: "", phone: "", message: "" });

      // Reset success message after 5 seconds
      setTimeout(() => {
        setSubmitStatus(null);
      }, 5000);
    } catch (error) {
      console.error("Failed to send contact form via EmailJS:", error);
      setSubmitStatus("error");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section id="contact" className="scroll-mt-24 md:scroll-mt-28 py-12 md:py-20 lg:py-32 bg-black relative border-t border-white/10">
      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-900 to-transparent"></div>
      
      <div className="container mx-auto px-4 md:px-6">
        <div className="flex flex-col items-center mb-8 md:mb-12 lg:mb-16 text-center">
          <h2 className="text-red-500 font-mono text-[10px] md:text-xs lg:text-sm tracking-widest mb-2">GET IN TOUCH</h2>
          <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-white mb-4 md:mb-6 lg:mb-8">Ready to <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-red-800 text-shadow-glow">Cyber secure</span> your perimeter?</h2>
          <p className="text-sm md:text-base lg:text-xl text-gray-400 mb-6 md:mb-8 lg:mb-10 max-w-2xl mx-auto">
        Join over 5,000 security professionals who trust CyberSec for their vulnerability assessments.
      </p>
        </div>

        <div className="flex flex-col gap-6 md:gap-8 lg:gap-12 xl:gap-16 justify-center items-center">
    
      

          {/* Contact Form */}
          <div className="relative w-1/2">
            <div className="p-4 md:p-6 lg:p-8 border border-white/10 bg-white/[0.02] rounded-lg relative overflow-hidden group hover:border-red-500/30 transition-all duration-300">
              <div className="absolute top-0 right-0 w-24 h-24 md:w-28 md:h-28 lg:w-32 lg:h-32 bg-red-600/10 blur-[60px] group-hover:bg-red-600/20 transition-all"></div>
              
              <div className="relative z-10">
                <form onSubmit={handleSubmit} className="space-y-4 md:space-y-5 lg:space-y-6">
                  <div>
                    <label htmlFor="name" className="block text-xs md:text-sm font-mono text-gray-400 mb-1.5 md:mb-2">
                      Full Name *
                    </label>
                    <input
                      type="text"
                      id="name"
                      name="name"
                      value={formData.name}
                      onChange={handleChange}
                      required
                      className="w-full px-3 md:px-4 py-2 md:py-2.5 lg:py-3 bg-black/50 border border-white/10 rounded-lg text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/50 transition-all font-mono text-xs md:text-sm"
                      placeholder="John Doe"
                    />
                  </div>

                  <div>
                    <label htmlFor="email" className="block text-xs md:text-sm font-mono text-gray-400 mb-1.5 md:mb-2">
                      Email Address *
                    </label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      required
                      className="w-full px-3 md:px-4 py-2 md:py-2.5 lg:py-3 bg-black/50 border border-white/10 rounded-lg text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/50 transition-all font-mono text-xs md:text-sm"
                      placeholder="john@example.com"
                    />
                  </div>

                  <div>
                    <label htmlFor="phone" className="block text-xs md:text-sm font-mono text-gray-400 mb-1.5 md:mb-2">
                      Phone Number *
                    </label>
                    <input
                      type="tel"
                      id="phone"
                      name="phone"
                      value={formData.phone}
                      onChange={handleChange}
                      required
                      className="w-full px-3 md:px-4 py-2 md:py-2.5 lg:py-3 bg-black/50 border border-white/10 rounded-lg text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/50 transition-all font-mono text-xs md:text-sm"
                      placeholder="+1 234 567 890"
                    />
                  </div>

            

                  <div>
                    <label htmlFor="message" className="block text-xs md:text-sm font-mono text-gray-400 mb-1.5 md:mb-2">
                      Message 
                    </label>
                    <textarea
                      id="message"
                      name="message"
                      value={formData.message}
                      onChange={handleChange}
                    
                      rows={5}
                      className="w-full px-3 md:px-4 py-2 md:py-2.5 lg:py-3 bg-black/50 border border-white/10 rounded-lg text-white placeholder-gray-600 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/50 transition-all resize-none font-mono text-xs md:text-sm"
                      placeholder="Tell us about your security needs..."
                    />
                  </div>

                  {submitStatus === 'success' && (
                    <div className="flex items-center gap-2 p-3 md:p-4 bg-green-900/20 border border-green-500/30 rounded-lg">
                      <CheckCircle className="w-4 h-4 md:w-5 md:h-5 text-green-500" />
                      <p className="text-green-400 text-xs md:text-sm font-mono">
                        Message sent successfully! We'll get back to you soon.
                      </p>
                    </div>
                  )}

                  {submitStatus === 'error' && (
                    <div className="flex items-center gap-2 p-3 md:p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
                      <AlertCircle className="w-4 h-4 md:w-5 md:h-5 text-red-500" />
                      <p className="text-red-400 text-xs md:text-sm font-mono">
                        Failed to send message. Please try again.
                      </p>
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full py-2.5 md:py-3 lg:py-4 bg-red-600 hover:bg-red-700 text-white font-bold font-mono rounded-lg transition-all duration-300 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(220,38,38,0.3)] hover:shadow-[0_0_30px_rgba(220,38,38,0.5)] text-xs md:text-sm"
                  >
                    {isSubmitting ? (
                      <>
                        <div className="w-4 h-4 md:w-5 md:h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        <span>Sending...</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-4 h-4 md:w-5 md:h-5" />
                        <span>Send Message</span>
                      </>
                    )}
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ContactUs;

