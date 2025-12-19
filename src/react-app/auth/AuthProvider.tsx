import type { Session, User } from "@supabase/supabase-js";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { supabase } from "@/react-app/lib/supabase";

export type Profile = {
  id: string;
  full_name: string;
  phone: string;
  email: string;
  created_at: string;
  updated_at: string;
};

type AuthContextValue = {
  user: User | null;
  session: Session | null;
  loading: boolean;
  profile: Profile | null;
  profileLoading: boolean;
  refreshProfile: () => Promise<void>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [profileLoading, setProfileLoading] = useState(false);

  const ensureProfileExists = async (sess: Session | null) => {
    const u = sess?.user;
    if (!u) return;

    // Only store profile details after the user is confirmed.
    const isConfirmed = Boolean((u as unknown as { email_confirmed_at?: string | null }).email_confirmed_at) || Boolean(u.confirmed_at);
    if (!isConfirmed) return;

    try {
      const { data: existing } = await supabase.from("profiles").select("id").eq("id", u.id).maybeSingle();
      if (existing?.id) return;

      const fullName =
        (u.user_metadata as Record<string, unknown> | null | undefined)?.full_name ||
        (u.user_metadata as Record<string, unknown> | null | undefined)?.name;

      const phone = (u.user_metadata as Record<string, unknown> | null | undefined)?.phone;

      await supabase.from("profiles").insert({
        id: u.id,
        full_name: typeof fullName === "string" && fullName.trim() ? fullName : "UNKNOWN",
        phone: typeof phone === "string" && phone.trim() ? phone : "UNKNOWN",
        email: u.email ?? "UNKNOWN",
      });
    } catch {
      // If this fails due to RLS/trigger timing/etc, we just leave profile null and let refreshProfile handle it later.
    }
  };

  useEffect(() => {
    let mounted = true;

    supabase.auth
      .getSession()
      .then(({ data }) => {
        if (!mounted) return;
        setSession(data.session ?? null);
        setUser(data.session?.user ?? null);
        setLoading(false);
      })
      .catch(() => {
        if (!mounted) return;
        setSession(null);
        setUser(null);
        setLoading(false);
      });

    const { data: sub } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setUser(nextSession?.user ?? null);
      setLoading(false);

      // Fire-and-forget: on sign-in after email confirmation link, ensure profiles row exists.
      void ensureProfileExists(nextSession);
    });

    return () => {
      mounted = false;
      sub.subscription.unsubscribe();
    };
  }, []);

  const refreshProfile = async () => {
    if (!user) {
      setProfile(null);
      setProfileLoading(false);
      return;
    }

    setProfileLoading(true);
    try {
      const { data, error } = await supabase.from("profiles").select("*").eq("id", user.id).maybeSingle();
      if (error) {
        // If profile doesn't exist yet (e.g., not confirmed), keep it null.
        setProfile(null);
        return;
      }
      setProfile((data as Profile | null) ?? null);
    } finally {
      setProfileLoading(false);
    }
  };

  useEffect(() => {
    void refreshProfile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      session,
      loading,
      profile,
      profileLoading,
      refreshProfile,
      signOut: async () => {
        await supabase.auth.signOut();
      },
    }),
    [loading, profile, profileLoading, session, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}


