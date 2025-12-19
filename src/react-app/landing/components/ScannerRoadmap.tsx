import { Play, Zap, Eye, Download, CheckCircle, ArrowRight } from 'lucide-react';

type ScannerRoadmapProps = {
  onOpenSignup: () => void;
};

const ScannerRoadmap = ({ onOpenSignup }: ScannerRoadmapProps) => {
  const steps = [
    {
      id: 1,
      title: "Initiate a Scan",
      icon: Play,
      description: "Start your security scan by selecting scan type and target",
      details: [
        "Choose Web or Mobile scan",
        "Enter target URL or upload app file",
        "Select scan type: Quick, Standard, or Comprehensive",
        "Click Start Scan - get instant scan ID"
      ],
      color: "red"
    },
    {
      id: 2,
      title: "Scanner Execution",
      icon: Zap,
      description: "Three powerful scanners run automatically in parallel",
      details: [
        "Standard Security Scanner: 20+ vulnerability types",
        "CWE Top 25 Scanner: Industry-standard weaknesses",
        "NIST SP 800-171 Compliance: Security controls assessment",
        "Results merged and deduplicated automatically"
      ],
      color: "red"
    },
    {
      id: 3,
      title: "View Scan Results",
      icon: Eye,
      description: "Comprehensive results with detailed vulnerability analysis",
      details: [
        "Real-time dashboard with auto-refresh",
        "Severity breakdown: Critical, High, Medium, Low",
        "CWE Top 25 ranked vulnerabilities",
        "NIST compliance percentage and controls status"
      ],
      color: "red"
    },
    {
      id: 4,
      title: "Export & Use Results",
      icon: Download,
      description: "Export reports in multiple formats for your team",
      details: [
        "Export formats: PDF, JSON, CSV, HTML",
        "Detailed evidence and remediation guidance",
        "Share with development teams",
        "Track compliance and remediation progress"
      ],
      color: "red"
    }
  ];

  return (
    <section id="roadmap" className="py-12 md:py-20 lg:py-32 bg-black relative border-t border-white/10">
      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-900 to-transparent"></div>
      
      <div className="container mx-auto px-4 md:px-6">
        {/* Header */}
        <div className="flex flex-col items-center mb-8 md:mb-12 lg:mb-16 text-center">
          <h2 className="text-red-500 font-mono text-[10px] md:text-xs lg:text-sm tracking-widest mb-2">SCANNER WORKFLOW</h2>
          <h3 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-white mb-3 md:mb-4">
            Step-by-Step <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-red-800 text-shadow-glow">Guide</span>
          </h3>
          <p className="text-gray-400 max-w-2xl text-sm md:text-base lg:text-lg">
            Learn how to use the CyberSec scanner in four simple steps
          </p>
        </div>

        {/* Roadmap Timeline */}
        <div className="relative">
          {/* Vertical Line (Desktop) */}
          <div className="hidden md:block absolute left-1/2 top-0 bottom-0 w-0.5 bg-gradient-to-b from-red-600 via-red-500 to-red-600 transform -translate-x-1/2"></div>

          {/* Steps */}
          <div className="space-y-8 md:space-y-12 lg:space-y-16 xl:space-y-24">
            {steps.map((step, index) => {
              const Icon = step.icon;
              const isEven = index % 2 === 0;
              
              return (
                <div
                  key={step.id}
                  className={`relative flex flex-col md:flex-row items-center gap-4 md:gap-6 lg:gap-8 ${
                    isEven ? 'md:flex-row' : 'md:flex-row-reverse'
                  }`}
                >
                  {/* Step Content Card */}
                  <div className={`w-full md:w-5/12 ${isEven ? 'md:text-right' : 'md:text-left'}`}>
                    <div className={`p-4 md:p-6 lg:p-8 border border-white/10 bg-white/[0.02] rounded-lg hover:border-red-500/30 hover:bg-white/[0.05] transition-all duration-300 relative overflow-hidden group ${
                      isEven ? 'md:mr-auto' : 'md:ml-auto'
                    }`}>
                      {/* Background Glow */}
                      <div className="absolute top-0 right-0 w-20 h-20 md:w-24 md:h-24 lg:w-32 lg:h-32 bg-red-600/10 blur-[60px] group-hover:bg-red-600/20 transition-all"></div>
                      
                      <div className="relative z-10">
                        {/* Step Number Badge */}
                        <div className={`inline-flex items-center gap-1.5 md:gap-2 px-2 md:px-3 lg:px-4 py-1 md:py-1.5 lg:py-2 rounded-full border border-red-500/30 bg-red-950/20 text-red-400 text-[10px] md:text-xs font-mono mb-3 md:mb-4 tracking-widest uppercase ${
                          isEven ? 'md:float-right' : 'md:float-left'
                        }`}>
                          <span>Step {step.id}</span>
                        </div>

                        {/* Title */}
                        <h4 className="text-lg md:text-xl lg:text-2xl font-bold text-white mb-2 md:mb-3 font-mono group-hover:text-red-400 transition-colors">
                          {step.title}
                        </h4>


                        {/* Description */}
                        <p className="text-gray-300 mb-4 md:mb-5 lg:mb-6 leading-relaxed text-sm md:text-base">
                          {step.description}
                        </p>

                        {/* Details List */}
                        <ul className="space-y-2 md:space-y-2.5 lg:space-y-3">
                          {step.details.map((detail, idx) => (
                            <li key={idx} className="flex items-start gap-2 md:gap-2.5 lg:gap-3">
                              <CheckCircle className="w-4 h-4 md:w-5 md:h-5 text-red-500 flex-shrink-0 mt-0.5" />
                              <span className="text-gray-400 text-xs md:text-sm leading-relaxed">{detail}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>

                  {/* Center Icon */}
                  <div className="hidden md:flex absolute left-1/2 transform -translate-x-1/2 w-12 h-12 md:w-14 md:h-14 lg:w-16 lg:h-16 bg-black border-4 border-red-600 rounded-full items-center justify-center z-10 shadow-[0_0_20px_rgba(220,38,38,0.5)]">
                    <Icon className="w-6 h-6 md:w-7 md:h-7 lg:w-8 lg:h-8 text-red-500" />
                  </div>

                  {/* Mobile Icon */}
                  <div className="md:hidden flex w-12 h-12 bg-black border-4 border-red-600 rounded-full items-center justify-center z-10 shadow-[0_0_20px_rgba(220,38,38,0.5)]">
                    <Icon className="w-6 h-6 text-red-500" />
                  </div>

                  {/* Spacer for alignment */}
                  <div className="hidden md:block w-5/12"></div>
                </div>
              );
            })}
          </div>
        </div>

        {/* CTA Section */}
        <div className="mt-12 md:mt-16 lg:mt-20 text-center">
          <div className="inline-flex flex-wrap items-center justify-center gap-2 md:gap-3 px-4 md:px-6 lg:px-8 py-3 md:py-4 bg-red-600/10 border border-red-500/30 rounded-lg">
            <ArrowRight className="w-4 h-4 md:w-5 md:h-5 text-red-500" />
            <span className="text-white font-mono font-bold text-sm md:text-base">Ready to start scanning?</span>
            <button 
              onClick={onOpenSignup}
              className="ml-2 md:ml-4 px-4 md:px-6 py-1.5 md:py-2 bg-red-600 hover:bg-red-700 text-white font-mono text-xs md:text-sm rounded-lg transition-all duration-300 shadow-[0_0_20px_rgba(220,38,38,0.3)] hover:shadow-[0_0_30px_rgba(220,38,38,0.5)]"
            >
              Get Started
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ScannerRoadmap;

