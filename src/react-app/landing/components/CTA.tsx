
const CTA = () => (
  <section className="py-24 bg-gradient-to-b from-black to-red-950/20 relative overflow-hidden">
    <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-20"></div>
    <div className="container mx-auto px-6 relative z-10 text-center">
      <h2 className="text-4xl md:text-5xl font-bold text-white mb-8">Ready to secure your perimeter?</h2>
      <p className="text-xl text-gray-400 mb-10 max-w-2xl mx-auto">
        Join over 5,000 security professionals who trust CyberSec for their vulnerability assessments.
      </p>
      <div className="flex flex-col sm:flex-row justify-center gap-4">
        <input 
          type="email" 
          placeholder="Enter your work email" 
          className="px-6 py-4 bg-black/50 border border-white/10 text-white rounded focus:outline-none focus:border-red-500 w-full sm:w-96"
        />
        <button className="px-8 py-4 bg-red-600 text-white font-bold font-mono hover:bg-red-700 transition-all">
          GET STARTED
        </button>
      </div>
    </div>
  </section>
);

export default CTA;




