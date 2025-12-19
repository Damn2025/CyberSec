import { createClient } from "@supabase/supabase-js";
import wranglerConfig from "../../../wrangler.json";

const supabaseUrl =
  import.meta.env.VITE_SUPABASE_URL || (wranglerConfig as { vars?: Record<string, string> }).vars?.SUPABASE_URL;
const supabaseAnonKey =
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
  (wranglerConfig as { vars?: Record<string, string> }).vars?.SUPABASE_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error(
    "Supabase URL/Key not configured. Set VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY (or configure wrangler.json vars).",
  );
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);




