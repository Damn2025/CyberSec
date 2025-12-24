import React from 'react';
import AstroremedisLogo from '../assets/images/Astroremedis.png';
import EduonixLogo from '../assets/images/eduonix.png';
import SipconLogo from '../assets/images/Sipcon.jpg';
import damnartLogo from '../assets/images/Damnart.png';
import eurocertLogo from '../assets/images/eurocert.webp';
import itcLogo from '../assets/images/itc.png';
import sustainableLogo from '../assets/images/Sustainable.jpg';
import grnataLogo from '../assets/images/Grnata.png';
import EurotechLogo from '../assets/images/Eurotech.png';
import MeddevicesLogo from '../assets/images/meddevices.png';

/**
 * TrustedBy Component
 * Marquee section displaying trusted organizations with logos
 */
const TrustedBy = () => {


  const companies = [
    { name: 'DamnArt', logo: damnartLogo, displayName: 'DamnArt' },
    { name: 'ITC India', logo: itcLogo, displayName: 'ITC India' },
    { name: 'Eurocert', logo: eurocertLogo, displayName: 'Eurocert' },
    { name: 'Eurotech', logo: EurotechLogo, displayName: 'Eurotech' },
    { name: 'Meddevices', logo: MeddevicesLogo, displayName: 'Meddevices' },
    { name: 'Sipcon', logo: SipconLogo, displayName: 'Sipcon' },
    { name: 'Sustainable Futures Trainings', logo: sustainableLogo, displayName: 'Sustainable Futures Trainings' },
    { name: 'Eduonix', logo: EduonixLogo, displayName: 'Eduonix' },
    { name: 'AstroRemedis', logo: AstroremedisLogo, displayName: 'AstroRemedis' },
    { name: 'Grnata', logo: grnataLogo, displayName: 'Grnata' },
  ];

  return (
    <section className="py-16 bg-[#0A0A0A] border-t border-b border-gray-900/50">
      <div className="container mx-auto px-6">
        <div className="text-center max-w-3xl mx-auto animate-on-scroll fade-in-up mb-16">
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-4">
            Powering <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-red-800">Businesses </span>Across Industries
          </h2>
          <p className="text-base sm:text-lg text-gray-400">
            Trusted by visionary organizations for 24/7 intelligence
          </p>
        </div>
        <div className="marquee animate-on-scroll fade-in">
          <div className="marquee-content gap-8 md:gap-12 pr-8 md:pr-12">
            {/* Duplicate content multiple times for seamless endless loop */}
            {[...companies, ...companies, ...companies, ...companies, ...companies, ...companies].map((company, index) => (
              <div
                key={index}
                className="marquee-item flex flex-col items-center justify-center gap-3 group min-w-[120px]"
              >
                {/* Logo */}
                <div className="relative w-16 h-20 md:w-20 md:h-20 flex items-center justify-center transition-all duration-300 group-hover:scale-125 bg-white rounded-lg p-2 md:p-3 group-hover:bg-gray-100 shadow-md group-hover:shadow-lg">
                  <img
                    src={company.logo}
                    alt={company.name}
                    className="w-full h-full object-contain grayscale group-hover:grayscale-0 transition-all duration-300"
                  />
                </div>
                {/* Company Name */}
                <div className="text-gray-400 text-sm md:text-base font-semibold text-center whitespace-nowrap group-hover:text-gray-300 transition-colors duration-300">
                  {
                    company.displayName
                  }
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default TrustedBy;
