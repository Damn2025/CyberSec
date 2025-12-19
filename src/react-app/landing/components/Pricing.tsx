import { CheckCircle, Gift } from 'lucide-react';

type PricingProps = {
  onOpenSignup?: () => void;
};

const Pricing = ({ onOpenSignup }: PricingProps) => {
  return (
    <section id="pricing" className="py-12 md:py-20 lg:py-32 bg-black relative">
       <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-900 to-transparent"></div>
       <div className="container mx-auto px-4 md:px-6">
         <div className="text-center mb-12 md:mb-16 lg:mb-20">
           <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white mb-3 md:mb-4">Simple, Transparent Access</h2>
           <p className="text-gray-400 text-sm md:text-base">No pricing tiers. Just full platform access, free for your first month.</p>
         </div>

         <div className="max-w-2xl mx-auto">
            <div className="group p-4 md:p-6 lg:p-8 rounded-2xl border border-red-600/60 bg-gradient-to-br from-red-950/40 via-black to-red-950/20 relative overflow-hidden hover:border-red-500 hover:shadow-[0_0_80px_rgba(220,38,38,0.45)] transition-all duration-500">
               <div className="absolute top-0 right-0 w-64 h-64 bg-red-600/10 blur-[80px] group-hover:bg-red-600/25 transition-all duration-500"></div>
               <div className="absolute -bottom-10 -left-10 w-56 h-56 bg-red-900/20 blur-[70px] group-hover:bg-red-900/30 transition-all duration-500"></div>
               
               <div className="relative z-10 text-center">
                  <div className="inline-flex items-center gap-2 px-4 py-1 mb-4 rounded-full bg-red-600/15 border border-red-500/40 text-[10px] md:text-xs font-mono uppercase tracking-[0.2em] text-red-300">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
                    <span>Launch Offer • Free for 30 Days</span>
                  </div>

                  <div className="inline-flex items-center justify-center w-16 h-16 md:w-20 md:h-20 mb-6 rounded-full bg-red-600/20 border border-red-500/40 shadow-[0_0_30px_rgba(220,38,38,0.5)] group-hover:shadow-[0_0_45px_rgba(220,38,38,0.8)] transition-all duration-500 group-hover:scale-110 animate-pulse">
                     <Gift className="w-8 h-8 md:w-10 md:h-10 text-red-500" />
                  </div>
                  
                  <h3 className="text-3xl md:text-4xl lg:text-5xl font-bold text-white mb-2 md:mb-3 font-mono tracking-tight">
                     Free for 1 Month
                  </h3>
                  <p className="text-xs md:text-sm text-red-300/80 mb-5 md:mb-7 font-mono uppercase tracking-[0.22em]">
                     No credit card • No contracts • No hidden fees
                  </p>
                  
                  <p className="text-sm md:text-base lg:text-lg text-gray-300 mb-8 md:mb-10 leading-relaxed max-w-xl mx-auto">
                     Start your security journey with unrestricted access to all scanners, dashboards, and reports. See real results across your web and mobile apps before you decide anything.
                  </p>
                  
                  <div className="space-y-4 md:space-y-5 mb-8 md:mb-10 text-left max-w-md mx-auto">
                     <div className="flex items-start gap-3 md:gap-4">
                        <CheckCircle className="w-5 h-5 md:w-6 md:h-6 text-red-500 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-300 text-sm md:text-base">Unlimited security scans for web and mobile applications</span>
                     </div>
                     <div className="flex items-start gap-3 md:gap-4">
                        <CheckCircle className="w-5 h-5 md:w-6 md:h-6 text-red-500 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-300 text-sm md:text-base">Access to all three scanner engines (Standard, CWE Top 25, NIST SP 800-171)</span>
                     </div>
                     <div className="flex items-start gap-3 md:gap-4">
                        <CheckCircle className="w-5 h-5 md:w-6 md:h-6 text-red-500 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-300 text-sm md:text-base">Comprehensive reporting with PDF, JSON, CSV, and HTML exports</span>
                     </div>
                     <div className="flex items-start gap-3 md:gap-4">
                        <CheckCircle className="w-5 h-5 md:w-6 md:h-6 text-red-500 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-300 text-sm md:text-base">Real-time dashboard with live scan monitoring</span>
                     </div>
                     <div className="flex items-start gap-3 md:gap-4">
                        <CheckCircle className="w-5 h-5 md:w-6 md:h-6 text-red-500 flex-shrink-0 mt-0.5" />
                        <span className="text-gray-300 text-sm md:text-base">Full access to vulnerability detection and remediation guidance</span>
                     </div>
                  </div>
                  
                  <button
                    onClick={onOpenSignup}
                    className="w-full max-w-xs mx-auto py-4 md:py-5 bg-red-600 text-white font-bold font-mono text-base md:text-lg rounded-lg shadow-[0_0_30px_rgba(220,38,38,0.55)] transition-all duration-300 hover:bg-red-700 hover:shadow-[0_0_45px_rgba(220,38,38,0.9)] hover:scale-110 hover:-translate-y-0.5"
                  >
                     Start Free Trial Now
                  </button>

                  <p className="text-gray-500 text-[10px] md:text-xs mt-4 md:mt-5">
                     Full platform access for 30 days. You decide what happens next.
                  </p>
               </div>
            </div>
         </div>
       </div>
    </section>
  );
};

export default Pricing;




