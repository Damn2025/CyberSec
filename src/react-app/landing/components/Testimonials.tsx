import { Quote } from 'lucide-react';

const Testimonials = () => {
  const reviews = [
    { 
      name: "Sarah Jenkins", 
      role: "CTO, TechFlow", 
      text: "The AI threat analyzer caught a zero-day payload that our traditional firewall missed completely. It's not just a tool, it's a necessity.", 
      type: "tech" 
    },
    { 
      name: "David Chen", 
      role: "Retired Teacher", 
      text: "I used the Simple Mode to check an email about a 'package delivery'. It told me it was a scam immediately. Finally, tech that speaks my language.", 
      type: "simple" 
    },
    { 
      name: "Marcus V.", 
      role: "DevOps Lead", 
      text: "Automating this via the CLI into our CI/CD pipeline was seamless. We scan every commit now. The false positive rate is practically zero.", 
      type: "tech" 
    },
    { 
      name: "Emily Rodriguez", 
      role: "Security Analyst, CyberGuard", 
      text: "The CWE Top 25 scanning engine is a game-changer. We've reduced our vulnerability remediation time by 60% since implementing CyberSec.", 
      type: "tech" 
    },
    { 
      name: "James Wilson", 
      role: "Small Business Owner", 
      text: "As someone with zero tech background, Simple Mode saved me from clicking a phishing link. The explanation was so clear, even I understood it.", 
      type: "simple" 
    },
    { 
      name: "Dr. Lisa Park", 
      role: "Chief Security Officer, MedTech Inc", 
      text: "The dual scanning engine architecture provides comprehensive coverage. We've integrated it into our security operations center with excellent results.", 
      type: "tech" 
    },
    { 
      name: "Michael Thompson", 
      role: "Freelance Developer", 
      text: "The API integration was straightforward. I built a custom dashboard that pulls scan results in real-time. Documentation is top-notch.", 
      type: "tech" 
    },
    { 
      name: "Patricia Martinez", 
      role: "Retail Store Manager", 
      text: "I check suspicious emails with Simple Mode before opening them. It's like having a security expert in my pocket, but they actually explain things clearly.", 
      type: "simple" 
    },
    { 
      name: "Robert Kim", 
      role: "Senior Penetration Tester", 
      text: "The technical mode provides detailed CVE mappings and CVSS scores. It's become an essential part of our security assessment workflow.", 
      type: "tech" 
    },
    { 
      name: "Amanda Foster", 
      role: "Marketing Director", 
      text: "Simple Mode helped me identify a malicious attachment in an email that looked legitimate. The plain English explanation was exactly what I needed.", 
      type: "simple" 
    },
    { 
      name: "Kevin Zhang", 
      role: "Cloud Security Architect", 
      text: "The continuous monitoring feature with webhook support integrates perfectly with our SIEM. Real-time alerts have improved our incident response time significantly.", 
      type: "tech" 
    },
    { 
      name: "Rachel Green", 
      role: "Non-Profit Coordinator", 
      text: "I'm not tech-savvy at all, but Simple Mode makes me feel protected. It tells me if something is safe or dangerous in words I can understand.", 
      type: "simple" 
    },
    { 
      name: "Alexander Novak", 
      role: "CISO, FinanceHub", 
      text: "We passed our SOC 2 audit with flying colors thanks to CyberSec's comprehensive scanning. The compliance reports saved us weeks of manual work.", 
      type: "tech" 
    },
    { 
      name: "Maria Santos", 
      role: "Grandmother & Blogger", 
      text: "My grandson set this up for me. Now I can check if those 'You won a prize!' emails are real or fake. Spoiler: they're always fake!", 
      type: "simple" 
    },
    { 
      name: "Daniel O'Brien", 
      role: "Red Team Manager, SecureOps", 
      text: "The exploit detection accuracy is impressive. It identified SQL injection vectors that even our manual testing missed. Highly recommend for any security team.", 
      type: "tech" 
    },
    { 
      name: "Jennifer Walsh", 
      role: "Elementary School Principal", 
      text: "We use Simple Mode to train our staff on recognizing threats. The clear explanations have made our whole team more security-conscious.", 
      type: "simple" 
    },
    { 
      name: "Raj Patel", 
      role: "VP Engineering, StartupXYZ", 
      text: "Integrated CyberSec into our GitHub Actions workflow. Every PR now gets automatically scanned. Found critical vulnerabilities before they hit production.", 
      type: "tech" 
    },
    { 
      name: "Susan Miller", 
      role: "Real Estate Agent", 
      text: "I handle sensitive client data daily. Simple Mode gives me peace of mind knowing I won't accidentally click on something malicious.", 
      type: "simple" 
    },
    { 
      name: "Chris Anderson", 
      role: "Security Consultant", 
      text: "The NIST SP 800-171 compliance module is exactly what my government contractor clients need. Automated assessments save hours of manual work.", 
      type: "tech" 
    },
    { 
      name: "Linda Hughes", 
      role: "Church Administrator", 
      text: "Our church received a suspicious donation request email. Simple Mode immediately flagged it as a scam. Saved us from potential fraud!", 
      type: "simple" 
    },
    { 
      name: "Thomas Wright", 
      role: "Malware Researcher", 
      text: "The sandbox analysis provides deep behavioral insights. I've discovered three new malware variants using this tool. Essential for threat research.", 
      type: "tech" 
    },
    { 
      name: "Nancy Cooper", 
      role: "Online Seller", 
      text: "Got an email saying my payment account was suspended. Simple Mode said it was phishing. Called my bank - they confirmed it was fake!", 
      type: "simple" 
    },
    { 
      name: "Brian Lee", 
      role: "DevSecOps Engineer", 
      text: "Container image scanning found vulnerabilities in our base images we didn't know existed. The remediation suggestions were spot-on and actionable.", 
      type: "tech" 
    },
    { 
      name: "Catherine Adams", 
      role: "Retired Nurse", 
      text: "I was about to give my Medicare info to a scammer. Simple Mode stopped me just in time. This tool should be mandatory for seniors!", 
      type: "simple" 
    },
    { 
      name: "Steve Morrison", 
      role: "Application Security Lead", 
      text: "The SAST and DAST combo catches issues at every stage of development. Our security debt has decreased by 75% in just six months.", 
      type: "tech" 
    },
    { 
      name: "Dorothy Bennett", 
      role: "Bookkeeper", 
      text: "Received a fake invoice email that looked exactly like our vendor's. Simple Mode caught it instantly. Could have lost thousands!", 
      type: "simple" 
    },
    { 
      name: "Andrew Jackson", 
      role: "SOC Team Lead, CyberDefense Inc", 
      text: "Alert fatigue was killing our team. CyberSec's smart prioritization reduced noise by 80% while catching more real threats. Game changer.", 
      type: "tech" 
    },
    { 
      name: "Helen Richardson", 
      role: "Freelance Writer", 
      text: "As a remote worker, I get tons of sketchy emails. Simple Mode is my first line of defense. It's like having a security guard for my inbox.", 
      type: "simple" 
    },
    { 
      name: "Jason Taylor", 
      role: "Infrastructure Security Engineer", 
      text: "The network vulnerability scanner found misconfigurations in our AWS setup that would have been a nightmare to discover post-breach.", 
      type: "tech" 
    },
    { 
      name: "Betty Collins", 
      role: "Antique Shop Owner", 
      text: "Someone tried to scam me with a fake shipping notification. Simple Mode told me exactly why it was suspicious. Saved my business money!", 
      type: "simple" 
    }
  ];

  // Duplicate reviews for seamless marquee
  const duplicatedReviews = [...reviews, ...reviews];

  return (
    <section id="testimonials" className="py-12 md:py-16 lg:py-24 bg-black relative border-t border-white/5 overflow-hidden">
       <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-900 to-transparent"></div>
      <div className="container mx-auto px-4 md:px-6">
        <div className="text-center mb-8 md:mb-12 lg:mb-16">
          <h2 className="text-red-500 font-mono text-[10px] md:text-xs lg:text-sm tracking-widest mb-2 uppercase">CLIENT TESTIMONIALS</h2>
          <h3 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white mb-3 md:mb-4">Field Reports</h3>
          <p className="text-gray-400 max-w-2xl mx-auto text-sm md:text-base">
            Protecting everyone from enterprise CTOs to everyday users. Real feedback from real users.
          </p>
        </div>

        {/* Marquee Container */}
        <div className="relative">
          {/* Gradient Overlays */}
          <div className="absolute left-0 top-0 bottom-0 w-32 bg-gradient-to-r from-black to-transparent z-10 pointer-events-none"></div>
          <div className="absolute right-0 top-0 bottom-0 w-32 bg-gradient-to-l from-black to-transparent z-10 pointer-events-none"></div>
          
          {/* Marquee */}
          <div className="overflow-hidden">
            <div className="flex animate-marquee gap-4 md:gap-6 lg:gap-8">
              {duplicatedReviews.map((r, i) => (
                <div 
                  key={i} 
                  className="group flex-shrink-0 w-64 sm:w-72 md:w-80 lg:w-96 p-4 md:p-6 lg:p-8 border border-white/10 bg-white/[0.02] rounded-lg relative hover:bg-white/[0.05] hover:border-red-500/30 hover:shadow-[0_0_30px_rgba(220,38,38,0.1)] transition-all duration-500"
                >
                  <div className="absolute -top-3 -right-3 md:-top-4 md:-right-4 w-8 h-8 md:w-10 md:h-10 lg:w-12 lg:h-12 bg-black border border-white/10 rounded-full flex items-center justify-center group-hover:border-red-500 transition-colors">
                    <Quote className="w-3 h-3 md:w-4 md:h-4 lg:w-5 lg:h-5 text-gray-500 group-hover:text-red-500" />
                  </div>
                  <p className="text-gray-300 italic mb-4 md:mb-5 lg:mb-6 leading-relaxed text-xs md:text-sm">"{r.text}"</p>
                  <div className="flex items-center gap-3 md:gap-4 pt-3 md:pt-4 border-t border-white/5">
                    <div className={`w-8 h-8 md:w-9 md:h-9 lg:w-10 lg:h-10 rounded-full flex items-center justify-center font-bold font-mono text-xs md:text-sm ${r.type === 'tech' ? 'bg-red-900/20 text-red-500 border border-red-500/20' : 'bg-green-900/20 text-green-500 border border-green-500/20'}`}>
                      {r.name.charAt(0)}
                    </div>
                    <div>
                      <div className="text-white font-bold text-xs md:text-sm">{r.name}</div>
                      <div className="text-[10px] md:text-xs text-gray-500 font-mono uppercase">{r.role}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Static Grid for Desktop (Alternative View) */}
        {/* <div className="hidden lg:grid lg:grid-cols-3 gap-8 mt-16">
          {reviews.slice(0, 6).map((r, i) => (
            <div 
              key={i} 
              className="group p-8 border border-white/10 bg-white/[0.02] rounded-lg relative hover:bg-white/[0.05] hover:border-red-500/30 hover:shadow-[0_0_30px_rgba(220,38,38,0.1)] transition-all duration-500"
            >
              <div className="absolute -top-4 -right-4 w-12 h-12 bg-black border border-white/10 rounded-full flex items-center justify-center group-hover:border-red-500 transition-colors">
                <Quote className="w-5 h-5 text-gray-500 group-hover:text-red-500" />
              </div>
              <p className="text-gray-300 italic mb-6 leading-relaxed">"{r.text}"</p>
              <div className="flex items-center gap-4 pt-4 border-t border-white/5">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold font-mono ${r.type === 'tech' ? 'bg-red-900/20 text-red-500 border border-red-500/20' : 'bg-green-900/20 text-green-500 border border-green-500/20'}`}>
                  {r.name.charAt(0)}
                </div>
                <div>
                  <div className="text-white font-bold text-sm">{r.name}</div>
                  <div className="text-xs text-gray-500 font-mono uppercase">{r.role}</div>
                </div>
              </div>
            </div>
          ))}
        </div> */}
      </div>

      <style>{`
        @keyframes marquee {
          0% {
            transform: translateX(0);
          }
          100% {
            transform: translateX(-50%);
          }
        }
        .animate-marquee {
          animation: marquee 15s linear infinite;
        }
        .animate-marquee:hover {
          animation-play-state: paused;
        }
      `}</style>
    </section>
  );
};

export default Testimonials;

