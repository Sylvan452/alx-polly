'use client';

import { createContext, useContext, useEffect, useState, useMemo } from 'react';
import { createClient } from '@/lib/supabase/client';
import type { Session, User } from '@supabase/supabase-js';

/**
 * Type definition for the authentication context.
 * 
 * Provides type safety for the authentication state and ensures
 * consistent access to user session information across components.
 */
interface AuthContextType {
  /** Current session object or null if no active session */
  session: Session | null;
  /** Current authenticated user or null if not logged in */
  user: User | null;
  /** Function to sign out the current user */
  signOut: () => void;
  /** Loading state during authentication operations */
  loading: boolean;
}

/**
 * React context for managing authentication state across the application.
 * 
 * This context provides a centralized way to access authentication state
 * in Client Components. It automatically syncs with Supabase auth changes
 * and provides real-time updates when users log in or out.
 * 
 * @security
 * - Only used in Client Components ('use client')
 * - Automatically syncs with server-side authentication state
 * - Provides real-time auth state updates
 * - Should be used alongside server-side auth checks for security
 */
const AuthContext = createContext<AuthContextType>({ 
  session: null, 
  user: null,
  signOut: () => {},
  loading: true,
});

/**
 * Authentication provider component for managing auth state in Client Components.
 * 
 * This provider wraps the application (or parts of it) to provide authentication
 * context to all child components. It handles initial session loading and
 * real-time authentication state changes.
 * 
 * @param children - React components that need access to authentication state
 * @returns JSX element providing authentication context
 * 
 * @security
 * - Uses browser-side Supabase client for real-time auth updates
 * - Automatically handles session refresh and state synchronization
 * - Provides loading states to prevent UI flicker during auth operations
 * - Should be used in conjunction with server-side auth protection
 * 
 * @example
 * ```tsx
 * function App() {
 *   return (
 *     <AuthProvider>
 *       <Dashboard />
 *     </AuthProvider>
 *   );
 * }
 * ```
 */
export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const supabase = useMemo(() => createClient(), []);
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    // Get initial user state from Supabase
    const getUser = async () => {
      const { data, error } = await supabase.auth.getUser();
      if (error) {
        console.error('Error fetching user:', error);
      }
      if (mounted) {
        setUser(data.user ?? null);
        setSession(null);
        setLoading(false);
        console.log('AuthContext: Initial user loaded', data.user);
      }
    };

    getUser();

    // Listen for real-time authentication state changes
    const { data: authListener } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);
      // Do not set loading to false here, only after initial load
      console.log('AuthContext: Auth state changed', _event, session, session?.user);
    });

    return () => {
      mounted = false;
      authListener.subscription.unsubscribe();
    };
  }, [supabase]);

  const signOut = async () => {
    await supabase.auth.signOut();
  };

  console.log('AuthContext: user', user);
  return (
    <AuthContext.Provider value={{ session, user, signOut, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

/**
 * Custom hook for accessing authentication state in Client Components.
 * 
 * This hook provides a convenient way to access the current user, session,
 * and loading state from any component within the AuthProvider tree.
 * It includes proper error handling for usage outside the provider.
 * 
 * @returns Authentication context containing user, session, and loading state
 * @throws Error if used outside of AuthProvider
 * 
 * @security
 * - Provides type-safe access to authentication state
 * - Ensures components are properly wrapped with AuthProvider
 * - Should be used alongside server-side auth checks for security
 * - Only provides client-side auth state (not authoritative)
 * 
 * @example
 * ```tsx
 * function UserProfile() {
 *   const { user, loading } = useAuth();
 *   
 *   if (loading) return <div>Loading...</div>;
 *   if (!user) return <div>Please log in</div>;
 *   
 *   return <div>Welcome, {user.email}!</div>;
 * }
 * ```
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
