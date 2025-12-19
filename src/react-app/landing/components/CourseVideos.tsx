import type { SyntheticEvent } from "react";
import { useState } from 'react';
import { Play, Clock, Users, Award, ExternalLink, ChevronLeft, ChevronRight } from 'lucide-react';

const CourseVideos = () => {
  const [currentPage, setCurrentPage] = useState(0);
  
  const courses = [
    {
      id: 1,
      title: "Introduction to Web Security",
      description: "Learn the fundamentals of web application security, common vulnerabilities, and best practices.",
      duration: "4h 30m",
      students: "12.5K",
      level: "Beginner",
      thumbnail: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=250&fit=crop",
      category: "Web Security"
    },
    {
      id: 2,
      title: "Advanced Penetration Testing",
      description: "Master advanced penetration testing techniques and ethical hacking methodologies.",
      duration: "8h 15m",
      students: "8.2K",
      level: "Advanced",
      thumbnail: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=400&h=250&fit=crop",
      category: "Penetration Testing"
    },
    {
      id: 3,
      title: "Mobile Security Fundamentals",
      description: "Comprehensive guide to securing Android and iOS applications against common threats.",
      duration: "5h 45m",
      students: "9.8K",
      level: "Intermediate",
      thumbnail: "https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=400&h=250&fit=crop",
      category: "Mobile Security"
    },
    {
      id: 4,
      title: "Network Security Essentials",
      description: "Understand network protocols, firewalls, and intrusion detection systems.",
      duration: "6h 20m",
      students: "15.3K",
      level: "Beginner",
      thumbnail: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=400&h=250&fit=crop",
      category: "Network Security"
    },
    {
      id: 5,
      title: "Cloud Security Architecture",
      description: "Design and implement secure cloud infrastructures for AWS, Azure, and GCP.",
      duration: "7h 10m",
      students: "6.5K",
      level: "Advanced",
      thumbnail: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=400&h=250&fit=crop",
      category: "Cloud Security"
    },
    {
      id: 6,
      title: "Incident Response & Forensics",
      description: "Learn how to detect, respond to, and investigate security incidents effectively.",
      duration: "5h 55m",
      students: "7.9K",
      level: "Intermediate",
      thumbnail: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=250&fit=crop",
      category: "Incident Response"
    }
  ];

  const coursesPerPage = 3;
  const totalPages = Math.ceil(courses.length / coursesPerPage);
  const startIndex = currentPage * coursesPerPage;
  const displayedCourses = courses.slice(startIndex, startIndex + coursesPerPage);

  const nextPage = () => {
    setCurrentPage((prev) => (prev + 1) % totalPages);
  };

  const prevPage = () => {
    setCurrentPage((prev) => (prev - 1 + totalPages) % totalPages);
  };

  return (
    <section id="courses" className="py-32 bg-black relative border-t border-white/10">
      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-red-900 to-transparent"></div>
      
      <div className="container mx-auto px-6">
        {/* Header */}
        <div className="flex flex-col items-center mb-16 text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-red-500/30 bg-red-950/20 text-red-400 text-xs font-mono mb-6 tracking-widest uppercase">
            <Award className="w-4 h-4" />
            Partnered with ITC
          </div>
          <h2 className="text-red-500 font-mono text-sm tracking-widest mb-2">CYBERSECURITY EDUCATION</h2>
          <h3 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Master <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-red-800 text-shadow-glow">Security</span> Skills
          </h3>
          <p className="text-gray-400 max-w-2xl text-lg">
            Comprehensive cybersecurity courses designed by industry experts. Learn from real-world scenarios and hands-on labs.
          </p>
        </div>

        {/* Course Grid */}
        <div className="relative">
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {displayedCourses.map((course) => (
              <div
                key={course.id}
                className="group border border-white/10 bg-white/[0.02] rounded-lg overflow-hidden hover:border-red-500/30 hover:bg-white/[0.05] transition-all duration-300 relative"
              >
                {/* Thumbnail */}
                <div className="relative h-48 bg-gradient-to-br from-gray-900 to-black overflow-hidden">
                  <img
                    src={course.thumbnail}
                    alt={course.title}
                    className="w-full h-full object-cover opacity-60 group-hover:opacity-80 transition-opacity"
                    onError={(e: SyntheticEvent<HTMLImageElement>) => {
                      e.currentTarget.style.display = 'none';
                    }}
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black via-transparent to-transparent"></div>
                  
                  {/* Play Button Overlay */}
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="w-16 h-16 bg-red-600/90 backdrop-blur-sm rounded-full flex items-center justify-center group-hover:scale-110 transition-transform cursor-pointer">
                      <Play className="w-8 h-8 text-white ml-1" fill="white" />
                    </div>
                  </div>

                  {/* Category Badge */}
                  <div className="absolute top-4 left-4">
                    <span className="px-3 py-1 bg-red-600/80 backdrop-blur-sm text-white text-xs font-mono rounded-full">
                      {course.category}
                    </span>
                  </div>

                  {/* Level Badge */}
                  <div className="absolute top-4 right-4">
                    <span className={`px-3 py-1 backdrop-blur-sm text-white text-xs font-mono rounded-full ${
                      course.level === 'Beginner' ? 'bg-green-600/80' :
                      course.level === 'Intermediate' ? 'bg-yellow-600/80' :
                      'bg-red-600/80'
                    }`}>
                      {course.level}
                    </span>
                  </div>
                </div>

                {/* Course Info */}
                <div className="p-6">
                  <h4 className="text-xl font-bold text-white mb-3 font-mono group-hover:text-red-500 transition-colors">
                    {course.title}
                  </h4>
                  <p className="text-gray-400 text-sm mb-4 leading-relaxed">
                    {course.description}
                  </p>

                  {/* Course Stats */}
                  <div className="flex items-center gap-4 text-sm text-gray-500 mb-4">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-4 h-4" />
                      <span className="font-mono">{course.duration}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Users className="w-4 h-4" />
                      <span className="font-mono">{course.students}</span>
                    </div>
                  </div>

                  {/* View Course Button */}
                  <button className="w-full py-3 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 text-red-400 hover:text-red-300 font-mono text-sm rounded-lg transition-all duration-300 flex items-center justify-center gap-2 group/btn">
                    <span>View Course</span>
                    <ExternalLink className="w-4 h-4 group-hover/btn:translate-x-1 transition-transform" />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Navigation Arrows */}
          {totalPages > 1 && (
            <>
              <button
                onClick={prevPage}
                className="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-4 md:-translate-x-12 w-12 h-12 bg-white/5 border border-white/10 rounded-full flex items-center justify-center hover:bg-white/10 hover:border-red-500/30 transition-all group"
                aria-label="Previous page"
              >
                <ChevronLeft className="w-6 h-6 text-gray-400 group-hover:text-red-500 transition-colors" />
              </button>
              <button
                onClick={nextPage}
                className="absolute right-0 top-1/2 -translate-y-1/2 translate-x-4 md:translate-x-12 w-12 h-12 bg-white/5 border border-white/10 rounded-full flex items-center justify-center hover:bg-white/10 hover:border-red-500/30 transition-all group"
                aria-label="Next page"
              >
                <ChevronRight className="w-6 h-6 text-gray-400 group-hover:text-red-500 transition-colors" />
              </button>
            </>
          )}

          {/* Page Indicators */}
          <div className="flex justify-center gap-2 mt-8">
            {Array.from({ length: totalPages }).map((_, index) => (
              <button
                key={index}
                onClick={() => setCurrentPage(index)}
                className={`w-2 h-2 rounded-full transition-all ${
                  currentPage === index
                    ? 'bg-red-500 w-8'
                    : 'bg-white/20 hover:bg-white/40'
                }`}
                aria-label={`Go to page ${index + 1}`}
              />
            ))}
          </div>
        </div>

        {/* ITC Partnership Info */}
        <div className="mt-16 p-8 border border-white/10 bg-white/[0.02] rounded-lg text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Award className="w-6 h-6 text-red-500" />
            <h4 className="text-white font-bold text-xl font-mono">ITC Partnership</h4>
          </div>
          <p className="text-gray-400 max-w-2xl mx-auto leading-relaxed">
            These courses are developed in partnership with <span className="text-red-500 font-bold">ITC </span>, 
            ensuring industry-standard curriculum and certification opportunities. All courses include hands-on labs, real-world scenarios, 
            and expert-led instruction.
          </p>
          <button className="mt-6 px-8 py-3 bg-red-600 hover:bg-red-700 text-white font-bold font-mono rounded-lg transition-all duration-300 shadow-[0_0_20px_rgba(220,38,38,0.3)] hover:shadow-[0_0_30px_rgba(220,38,38,0.5)]">
            Explore All Courses
          </button>
        </div>
      </div>
    </section>
  );
};

export default CourseVideos;

