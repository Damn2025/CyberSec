import { Navigate, useLocation } from "react-router";
import { useAuth } from "@/react-app/auth/AuthProvider";

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-sm text-gray-400">Loading...</div>
      </div>
    );
  }

  if (!user) return <Navigate to="/" replace state={{ from: location }} />;

  return <>{children}</>;
}















