import type { LucideIcon } from "lucide-react";

type FeatureCardProps = {
  icon: LucideIcon;
  title: string;
  desc: string;
};

const FeatureCard = ({ icon: Icon, title, desc }: FeatureCardProps) => (
  <div className="p-8 border border-white/5 bg-white/[0.02] hover:bg-white/[0.05] hover:border-red-500/30 transition-all duration-300 group rounded-lg relative overflow-hidden">
    <div className="absolute top-0 right-0 w-24 h-24 bg-red-600/10 blur-[50px] group-hover:bg-red-600/20 transition-all"></div>
    <Icon className="w-10 h-10 text-red-500 mb-6 group-hover:scale-110 transition-transform duration-300" />
    <h3 className="text-xl font-bold text-white mb-3 font-mono">{title}</h3>
    <p className="text-gray-400 leading-relaxed text-sm">{desc}</p>
  </div>
);

export default FeatureCard;



