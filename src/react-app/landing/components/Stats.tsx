
const Stats = () => (
  <section className="py-20 ">
    <div className="container mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-12 text-center">
      <div>
        <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">10<span className="text-red-600">k+</span></div>
        <div className="text-gray-500 text-sm uppercase tracking-widest">Threats Blocked</div>
      </div>
      <div>
        <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">99<span className="text-red-600">.9%</span></div>
        <div className="text-gray-500 text-sm uppercase tracking-widest">Uptime</div>
      </div>
      <div>
        <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">0<span className="text-red-600">ms</span></div>
        <div className="text-gray-500 text-sm uppercase tracking-widest">Latency</div>
      </div>
      <div>
        <div className="text-4xl md:text-5xl font-bold text-white mb-2 font-mono">24<span className="text-red-600">/7</span></div>
        <div className="text-gray-500 text-sm uppercase tracking-widest">Support</div>
      </div>
    </div>
  </section>
);

export default Stats;





