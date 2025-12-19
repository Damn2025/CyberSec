import { useState } from 'react';
import { Globe, Shield, BarChart, CheckCircle, Zap, Award } from 'lucide-react';
import ABC from '../assets/images/Web_Photo_Editor.jpg';
import ABC2 from '../assets/images/ABC2.jpg';
import ABC3 from '../assets/images/ABC3.png';
import ABC4 from '../assets/images/ABC4.png';
import ABC5 from '../assets/images/ABC5.png';


const Features = () => {
  const features = [
    { 
      icon: Globe, 
      title: "Multi-platform Security Scanning", 
      desc: "Comprehensive security scanning for web and mobile applications with unified management.",
      details: [
        "Web application scanning: scans websites and web apps for vulnerabilities",
        "Mobile application scanning: supports Android (APK) and iOS (IPA) binaries",
        "Unified dashboard: manage web and mobile scans in one interface",
        "Multiple scan types: Quick, Standard, and Comprehensive"
      ],
      img: ABC
    },
    { 
      icon: Zap, 
      title: "Triple Scanner Engine (Parallel Scanning)", 
      desc: "Three powerful scanners running simultaneously for comprehensive and fast vulnerability detection.",
      details: [
        "Standard security scanner: detects 20+ vulnerability types (SQL injection, XSS, CSRF, command injection, path traversal, etc.)",
        "CWE Top 25 scanner: checks against the 2024 CWE Top 25 Most Dangerous Software Weaknesses with ranked detection",
        "NIST SP 800-171 compliance scanner: assesses compliance with NIST SP 800-53A Rev 5 controls (RA-05, SA-11, SI-02)",
        "Parallel execution: all three scanners run simultaneously for faster results"
      ],
      img: ABC2
    
    },
    { 
      icon: Shield, 
      title: "Vulnerability Detection Coverage", 
      desc: "Extensive coverage of security vulnerabilities across web, mobile, and API endpoints.",
      details: [
        "Injection vulnerabilities: SQL injection, XSS, command injection, code injection, XXE",
        "Authentication and authorization: weak authentication, missing authorization, session management flaws",
        "Security misconfigurations: security headers, SSL/TLS, CORS, API security, information disclosure",
        "Advanced threats: SSRF, insecure deserialization, business logic flaws, rate limiting, file upload vulnerabilities",
        "Mobile-specific: OWASP Mobile Top 10, insecure data storage, code obfuscation, certificate pinning"
      ],
      img: ABC3
  
    },
    { 
      icon: Award, 
      title: "Compliance and Standards-Based Assessment", 
      desc: "Industry-standard compliance checking and vulnerability ranking aligned with major security frameworks.",
      details: [
        "CWE Top 25 mapping: ranks vulnerabilities 1–25 with CWE IDs and scores",
        "NIST SP 800-171 compliance: checks compliance with requirements, shows compliance percentage, and tracks requirements met/total",
        "CVSS scoring: assigns standardized severity scores",
        "Industry standards: aligns with OWASP Top 10, CWE, and NIST frameworks"
      ],
      img: ABC4
    },
    { 
      icon: BarChart, 
      title: "Reporting and Analytics", 
      desc: "Comprehensive reporting with multiple export formats, evidence collection, and real-time monitoring.",
      details: [
        "Multiple export formats: PDF, JSON, CSV, HTML",
        "Evidence collection: proof-of-concept, detection evidence, and code snippets",
        "Remediation guidance: actionable recommendations for each vulnerability",
        "Real-time dashboard: live scan monitoring, auto-refreshing status, severity breakdowns",
        "Historical tracking: scan history, vulnerability trends, and compliance metrics"
      ],
        img: ABC5
    }
  ];

  const [selectedFeature, setSelectedFeature] = useState(0);

  return (
    <section id="features" className="py-12 md:py-20 lg:py-32 bg-black relative">
      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-900 to-transparent"></div>
      
      <div className="container mx-auto px-4 md:px-6">
        <div className="flex flex-col justify-between items-center mb-8 md:mb-12 lg:mb-16 gap-4 md:gap-6 text-center">
          <div className="max-w-xl">
             <h2 className="text-red-500 font-mono text-[10px] md:text-xs lg:text-sm tracking-widest mb-2">SYSTEM FEATURES</h2>
             <h3 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white">Military-Grade <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-red-800 text-shadow-glow">Protection</span></h3>
          </div>
          <p className="text-gray-400 max-w-md text-right md:text-left">
           
          </p>
        </div>

        {/* Mobile View - Individual Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 md:hidden">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <div
                key={index}
                className="p-4 md:p-6 lg:p-8 border border-white/5 bg-white/[0.02] hover:bg-white/[0.05] hover:border-red-500/30 transition-all duration-300 group rounded-lg relative overflow-hidden"
              >
                <div className="absolute top-0 right-0 w-16 h-16 md:w-24 md:h-24 bg-red-600/10 blur-[50px] group-hover:bg-red-600/20 transition-all"></div>
                <Icon className="w-6 h-6 md:w-8 md:h-8 lg:w-10 lg:h-10 text-red-500 mb-3 md:mb-4 lg:mb-6 group-hover:scale-110 transition-transform duration-300 relative z-10" />
                <h3 className="text-base md:text-lg lg:text-xl font-bold text-white mb-2 md:mb-3 font-mono relative z-10">{feature.title}</h3>
                <p className="text-gray-400 leading-relaxed text-xs md:text-sm mb-3 md:mb-4 relative z-10">{feature.desc}</p>
                <div className="border-t border-white/10 pt-3 md:pt-4 relative z-10">
                  <h4 className="text-[10px] md:text-xs font-mono text-red-500 uppercase tracking-widest mb-2 md:mb-3">
                    Key Points
                  </h4>
                  <ul className="space-y-1.5 md:space-y-2">
                    {feature.details.slice(0, 3).map((detail, idx) => (
                      <li key={idx} className="flex items-start gap-1.5 md:gap-2">
                        <div className="w-1 h-1 md:w-1.5 md:h-1.5 rounded-full bg-red-500 mt-1 md:mt-1.5 shrink-0"></div>
                        <span className="text-gray-400 text-[10px] md:text-xs leading-relaxed">{detail}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            );
          })}
        </div>

        {/* Desktop View - Left Column + Right Card */}
        <div className="hidden md:grid md:grid-cols-2 gap-4 md:gap-6 lg:gap-8 xl:gap-12">
          {/* Left Column - Feature List */}
          <div className="space-y-3 md:space-y-4">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              const isSelected = selectedFeature === index;
              
              return (
                <button
                  key={index}
                  onClick={() => setSelectedFeature(index)}
                  className={`w-full text-left p-4 md:p-5 lg:p-6 border rounded-lg transition-all duration-300 group ${
                    isSelected
                      ? 'border-red-500/50 bg-red-950/20 shadow-[0_0_20px_rgba(220,38,38,0.2)]'
                      : 'border-white/5 bg-white/[0.02] hover:border-red-500/30 hover:bg-white/[0.05]'
                  }`}
                >
                  <div className="flex items-start gap-3 md:gap-4">
                    <div className={`p-2 md:p-2.5 lg:p-3 rounded-lg transition-all duration-300 ${
                      isSelected 
                        ? 'bg-red-600/20 text-red-500' 
                        : 'bg-white/5 text-gray-400 group-hover:text-red-500'
                    }`}>
                      <Icon className="w-5 h-5 md:w-6 md:h-6" />
                    </div>
                    <div className="flex-1">
                      <h3 className={`text-base md:text-lg font-bold mb-1 md:mb-2 font-mono transition-colors ${
                        isSelected ? 'text-white' : 'text-gray-300 group-hover:text-white'
                      }`}>
                        {feature.title}
                      </h3>
                      <p className={`text-xs md:text-sm leading-relaxed transition-colors ${
                        isSelected ? 'text-gray-300' : 'text-gray-500'
                      }`}>
                        {feature.desc}
                      </p>
                    </div>
                    {isSelected && (
                      <CheckCircle className="w-4 h-4 md:w-5 md:h-5 text-red-500 flex-shrink-0 mt-1" />
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right Column - Selected Feature Card */}
          <div className="relative">
            <div className="sticky top-24 p-4 md:p-6 lg:p-8 border border-white/10 bg-white/[0.02] rounded-lg relative overflow-hidden group hover:bg-white/[0.05] hover:border-red-500/30 transition-all duration-300">
              <div className="absolute top-0 right-0 w-24 h-24 md:w-32 md:h-32 bg-red-600/10 blur-[60px] group-hover:bg-red-600/20 transition-all"></div>
              
              <div className="relative z-10">
                <div className="flex items-center gap-3 md:gap-4 mb-4 md:mb-6">
                  <div className="p-3 md:p-4 bg-red-600/20 rounded-lg">
                    {(() => {
                      const Icon = features[selectedFeature].icon;
                      return <Icon className="w-8 h-8 md:w-10 md:h-10 text-red-500" />;
                    })()}
                  </div>
                  <div>
                    <h3 className="text-xl md:text-2xl font-bold text-white mb-1 font-mono">
                      {features[selectedFeature].title}
                    </h3>
                    <p className="text-xs md:text-sm text-gray-400 font-mono">
                      {features[selectedFeature].desc}
                    </p>
                  </div>
                </div>

                <div className="border-t border-white/10 pt-4 md:pt-6 overflow-visible">
                  <img src={features[selectedFeature].img} alt="Feature illustration" className="w-full h-auto object-contain" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
    </section>
  );
};

export default Features;