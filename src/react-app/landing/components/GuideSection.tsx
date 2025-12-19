
const GuideSection = () => {
  return (
    <section id="how-it-works" className="py-24 ">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-bold text-white mb-4">Not a Tech Expert? No Problem.</h2>
          <p className="text-gray-400">Use our "Simple Mode" to analyze everyday threats.</p>
        </div>
        <div className="grid md:grid-cols-3 gap-8">
          <div className="relative p-6 rounded-lg border border-white/10 bg-black/50 group hover:border-red-500/30 transition-all duration-300">
            <div className="absolute -top-4 -left-4 w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center font-bold text-xl text-white shadow-[0_0_15px_rgba(220,38,38,0.5)]">1</div>
            <div className="mt-4">
              <h3 className="text-xl font-bold text-white mb-2 font-mono">Copy the Content</h3>
              <p className="text-gray-400 text-sm">Got a weird email, a strange text message, or an error code? Just copy the text to your clipboard.</p>
            </div>
          </div>
          <div className="relative p-6 rounded-lg border border-white/10 bg-black/50 group hover:border-green-500/30 transition-all duration-300">
            <div className="absolute -top-4 -left-4 w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center font-bold text-xl text-white shadow-[0_0_15px_rgba(220,38,38,0.5)]">2</div>
            <div className="mt-4">
              <h3 className="text-xl font-bold text-white mb-2 font-mono">Select Simple Mode</h3>
              <p className="text-gray-400 text-sm">Scroll to our AI Analyzer above. Click the <span className="text-green-500 font-bold">Simple Mode</span> button to switch to plain English.</p>
            </div>
            <div className="mt-4 flex justify-center"><div className="px-3 py-1 rounded-full bg-green-600 text-white text-xs font-bold shadow-lg">Simple Mode</div></div>
          </div>
          <div className="relative p-6 rounded-lg border border-white/10 bg-black/50 group hover:border-red-500/30 transition-all duration-300">
            <div className="absolute -top-4 -left-4 w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center font-bold text-xl text-white shadow-[0_0_15px_rgba(220,38,38,0.5)]">3</div>
            <div className="mt-4">
              <h3 className="text-xl font-bold text-white mb-2 font-mono">Get Instant Advice</h3>
              <p className="text-gray-400 text-sm">Hit analyze. We'll tell you if it's safe or a scam, and exactly what to do next.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default GuideSection;



