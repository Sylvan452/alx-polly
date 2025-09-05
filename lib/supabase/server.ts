import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

/**
 * Creates a Supabase client for server-side usage with enhanced security.
 * 
 * This client is designed for use in Server Components, Server Actions, and API routes.
 * It uses the service role key for elevated permissions and handles cookie-based
 * session management on the server side. This provides secure access to Supabase
 * features without exposing sensitive credentials to the client.
 * 
 * @returns Promise resolving to configured Supabase client for server usage
 * 
 * @security
 * - Uses service role key (server-side only, never exposed to client)
 * - Handles secure cookie management for session persistence
 * - Bypasses Row Level Security when using service role key
 * - Should only be used in server-side contexts (Server Components, Actions, API routes)
 * 
 * @example
 * ```typescript
 * // In a Server Component or Server Action
 * import { createClient } from '@/lib/supabase/server';
 * 
 * const supabase = await createClient();
 * const { data: user } = await supabase.auth.getUser();
 * ```
 */
export async function createClient() {
  const cookieStore = await cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            );
          } catch {
            // The `setAll` method was called from a Server Component.
            // This can be ignored if you have middleware refreshing
            // user sessions.
          }
        },
      },
    }
  );
}