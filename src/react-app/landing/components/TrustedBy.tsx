import { Globe, Shield, Server, Cpu, Database, Lock, Zap, Network, Cloud, Code, Terminal, Activity } from 'lucide-react';

const TrustedBy = () => {
  const companies = [
    { name: "TECH_GLOBAL", icon: Globe },
    { name: "NET_DEFENSE", icon: Shield },
    { name: "DATA_CORE", icon: Server },
    { name: "AI_SYSTEMS", icon: Cpu },
    { name: "SECURE_NET", icon: Lock },
    { name: "CLOUD_GUARD", icon: Database },
    { name: "POWER_SYS", icon: Zap },
    { name: "NETWORK_X", icon: Network },
    { name: "CLOUD_TECH", icon: Cloud },
    { name: "CODE_SEC", icon: Code },
    { name: "TERMINAL_PRO", icon: Terminal },
    { name: "ACTIVE_DEF", icon: Activity }
  ];

  // Duplicate companies for seamless marquee
  const duplicatedCompanies = [...companies, ...companies, ...companies];

  return (
    <section className="py-16 md:py-24 bg-black border-b border-white/5 relative overflow-hidden">
      <div className="absolute inset-0 cyber-grid opacity-10"></div>
      <div className="container mx-auto px-6 relative z-10">
        <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white mb-4 text-center font-poppins px-4">
          <span className="text-red-600">Security</span> Trusted by Teams Everywhere
        </h2>
        <p className="text-gray-500 text-xs font-mono tracking-widest mb-8 md:mb-12 uppercase text-center px-4">
          Securing Infrastructure For Industry Leaders
        </p>
        
        {/* Marquee Container */}
        <div className="relative">
          {/* Gradient Overlays */}
          <div className="absolute left-0 top-0 bottom-0 w-20 md:w-32 bg-gradient-to-r from-black via-black to-transparent z-10 pointer-events-none"></div>
          <div className="absolute right-0 top-0 bottom-0 w-20 md:w-32 bg-gradient-to-l from-black via-black to-transparent z-10 pointer-events-none"></div>
          
          {/* Marquee */}
          <div className="overflow-hidden">
            <div className="flex animate-marquee gap-6 md:gap-12">
              {duplicatedCompanies.map((company, idx) => {
                const Icon = company.icon;
                return (
                  <div 
                    key={idx} 
                    className="flex-shrink-0 flex items-center justify-center gap-3 group cursor-pointer px-4 py-3 border border-white/10 rounded-lg bg-white/[0.02] hover:bg-white/[0.05] hover:border-red-500/30 transition-all duration-300"
                  >
                    <Icon className="w-5 h-5 sm:w-6 sm:h-6 md:w-7 md:h-7 text-gray-600 group-hover:text-red-500 transition-colors duration-300" />
                    <span className="font-mono text-sm sm:text-base md:text-lg font-bold text-gray-600 group-hover:text-white transition-colors duration-300 whitespace-nowrap">
                      {company.name}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Static Grid for Mobile (Alternative View) */}
        {/* <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4 md:gap-6 mt-8 md:hidden">
          {companies.slice(0, 6).map((company, idx) => {
            const Icon = company.icon;
            return (
              <div 
                key={idx} 
                className="flex flex-col items-center justify-center gap-2 group cursor-pointer p-4 border border-white/10 rounded-lg bg-white/[0.02] hover:bg-white/[0.05] hover:border-red-500/30 transition-all duration-300"
              >
                <Icon className="w-6 h-6 text-gray-600 group-hover:text-red-500 transition-colors duration-300" />
                <span className="font-mono text-xs font-bold text-gray-600 group-hover:text-white transition-colors duration-300 text-center">
                  {company.name}
                </span>
              </div>
            );
          })}
        </div> */}
      </div>

      <style>{`
        @keyframes marquee {
          0% {
            transform: translateX(0);
          }
          100% {
            transform: translateX(-33.333%);
          }
        }
        .animate-marquee {
          animation: marquee 40s linear infinite;
        }
        .animate-marquee:hover {
          animation-play-state: paused;
        }
      `}</style>
    </section>
  );
};

export default TrustedBy;
