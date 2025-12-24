import { Target, Eye, Code, Lock, Cpu } from 'lucide-react';

const AboutSection = () => {
  return (
    <section id="about" className="py-12 md:py-16 lg:py-24 bg-black relative">
      <div className="container mx-auto px-4 md:px-6">
        <div className="flex flex md:flex-row sm: flex-col items-center gap-8 md:gap-12 lg:gap-16">
          <div className="w-full md:w-1/2">
            <div className="inline-flex items-center gap-1.5 md:gap-2 px-2 md:px-3 py-0.5 md:py-1 rounded-full border border-red-500/30 bg-red-950/20 text-red-400 text-[10px] md:text-xs font-poppins mb-4 md:mb-6 tracking-widest uppercase">
              <Target className="w-2.5 h-2.5 md:w-3 md:h-3" /> Mission Protocol
            </div>
            <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white mb-4 md:mb-6 leading-tight font-poppins">
              We Are The <span className="text-red-600">Digital Firewall</span> For The Modern World.
            </h2>
            <h3 className="text-gray-400 mb-4 md:mb-6 leading-relaxed font-poppins text-sm md:text-base">
            <span className="text-shadow-glow font-bold text-white">CYBER<span className="text-red-600">SEC</span></span> helps businesses stay safe in the digital world by constantly keeping an eye on their online presence. We identify <span className="text-red-500 font-semibold">risks</span>, <span className="text-red-500 font-semibold">weaknesses</span>, and potential <span className="text-red-500 font-semibold">threats</span> before they turn into real problems.
            </h3>
            <p className="text-gray-400 mb-6 md:mb-8 leading-relaxed font-poppins text-sm md:text-base">
            Our platform gives you a clear, easy-to-understand view of your <span className="text-white font-semibold">security</span> — not just within your own systems, but also across the <span className="text-white font-semibold">partners</span> and <span className="text-white font-semibold">vendors</span> you rely on. This means you know where your business stands at all times.
            </p>
            <p className="text-gray-400 mb-6 md:mb-8 leading-relaxed font-poppins text-sm md:text-base">
            With <span className="text-shadow-glow font-bold text-white">CYBER<span className="text-red-600">SEC</span></span>, you don't need multiple tools or complex setups. Everything is brought together in one place, helping you spot issues early, reduce exposure, and make smarter security decisions with confidence.
            </p>
            </div>
          
          <div className="w-full md:w-1/2 grid grid-cols-2 gap-2 md:gap-3 lg:gap-4">
            <div className="space-y-2 md:space-y-3 lg:space-y-4 mt-4 md:mt-6 lg:mt-8">
              <div className="h-32 md:h-40 lg:h-48 bg-gradient-to-br from-gray-900 to-black border border-white/10 rounded-lg p-3 md:p-4 lg:p-6 flex flex-col justify-end group hover:border-red-500/30 transition-all duration-500">
                <Eye className="w-5 h-5 md:w-6 md:h-6 lg:w-8 lg:h-8 text-red-600 mb-2 md:mb-3 lg:mb-4 group-hover:scale-110 transition-transform" />
                <h4 className="text-white font-poppins font-bold text-sm md:text-base">Surveillance</h4>
              </div>
              <div className="h-28 md:h-32 lg:h-40 bg-gradient-to-br from-gray-900 to-black border border-white/10 rounded-lg p-3 md:p-4 lg:p-6 flex flex-col justify-end group hover:border-red-500/30 transition-all duration-500">
                <Code className="w-5 h-5 md:w-6 md:h-6 lg:w-8 lg:h-8 text-red-600 mb-2 md:mb-3 lg:mb-4 group-hover:scale-110 transition-transform" />
                <h4 className="text-white font-poppins font-bold text-sm md:text-base">Secure Code</h4>
              </div>
            </div>
            <div className="space-y-2 md:space-y-3 lg:space-y-4">
              <div className="h-28 md:h-32 lg:h-40 bg-gradient-to-br from-gray-900 to-black border border-white/10 rounded-lg p-3 md:p-4 lg:p-6 flex flex-col justify-end group hover:border-red-500/30 transition-all duration-500">
                <Lock className="w-5 h-5 md:w-6 md:h-6 lg:w-8 lg:h-8 text-red-600 mb-2 md:mb-3 lg:mb-4 group-hover:scale-110 transition-transform" />
                <h4 className="text-white font-poppins font-bold text-sm md:text-base">Encryption</h4>
              </div>
              <div className="h-32 md:h-40 lg:h-48 bg-gradient-to-br from-gray-900 to-black border border-white/10 rounded-lg p-3 md:p-4 lg:p-6 flex flex-col justify-end group hover:border-red-500/30 transition-all duration-500">
                <Cpu className="w-5 h-5 md:w-6 md:h-6 lg:w-8 lg:h-8 text-red-600 mb-2 md:mb-3 lg:mb-4 group-hover:scale-110 transition-transform" />
                <h4 className="text-white font-poppins font-bold text-sm md:text-base">AI Defense</h4>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default AboutSection;


