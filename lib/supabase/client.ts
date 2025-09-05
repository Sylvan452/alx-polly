import { createBrowserClient } from '@supabase/ssr';

/**
 * Creates a Supabase client for browser/client-side usage.
 * 
 * This client is designed for use in Client Components and browser environments.
 * It automatically handles cookie-based session management and provides access
 * to Supabase authentication and database features from the client side.
 * 
 * @returns Configured Supabase client for browser usage
 * 
 * @security
 * - Uses public anon key (safe for client-side exposure)
 * - Automatically manages authentication cookies
 * - Respects Row Level Security (RLS) policies
 * - Should only be used in Client Components ('use client')
 * 
 * @example
 * ```typescript
 * 'use client';
 * import { createClient } from '@/lib/supabase/client';
 * 
 * const supabase = createClient();
 * const { data: user } = await supabase.auth.getUser();
 * ```
 */
export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}
