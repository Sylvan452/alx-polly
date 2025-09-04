// Enhanced session management utilities
import { createClient } from "@/lib/supabase/server";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export interface SessionConfig {
  maxAge: number; // Session timeout in seconds
  renewalThreshold: number; // Renew session if it expires within this many seconds
  requireReauth: boolean; // Require re-authentication for sensitive operations
}

export const DEFAULT_SESSION_CONFIG: SessionConfig = {
  maxAge: 24 * 60 * 60, // 24 hours
  renewalThreshold: 60 * 60, // 1 hour
  requireReauth: false,
};

export const SENSITIVE_SESSION_CONFIG: SessionConfig = {
  maxAge: 15 * 60, // 15 minutes for sensitive operations
  renewalThreshold: 5 * 60, // 5 minutes
  requireReauth: true,
};

/**
 * Enhanced session validation with timeout and renewal
 * @param config - Session configuration
 * @returns Session validation result
 */
export async function validateSession(config: SessionConfig = DEFAULT_SESSION_CONFIG) {
  const supabase = await createClient();
  
  try {
    const { data: { session }, error } = await supabase.auth.getSession();
    
    if (error || !session) {
      return {
        valid: false,
        user: null,
        session: null,
        needsRenewal: false,
        error: 'No valid session found'
      };
    }

    const now = Math.floor(Date.now() / 1000);
    const sessionAge = now - (session.issued_at || 0);
    const timeUntilExpiry = (session.expires_at || 0) - now;
    
    // Check if session has exceeded max age
    if (sessionAge > config.maxAge) {
      await invalidateSession();
      return {
        valid: false,
        user: null,
        session: null,
        needsRenewal: false,
        error: 'Session expired due to max age'
      };
    }
    
    // Check if session needs renewal
    const needsRenewal = timeUntilExpiry < config.renewalThreshold;
    
    if (needsRenewal) {
      const renewalResult = await renewSession();
      if (!renewalResult.success) {
        return {
          valid: false,
          user: null,
          session: null,
          needsRenewal: false,
          error: 'Failed to renew session'
        };
      }
    }
    
    return {
      valid: true,
      user: session.user,
      session,
      needsRenewal,
      sessionAge,
      timeUntilExpiry
    };
  } catch (error) {
    console.error('Session validation error:', error);
    return {
      valid: false,
      user: null,
      session: null,
      needsRenewal: false,
      error: 'Session validation failed'
    };
  }
}

/**
 * Renew the current session
 * @returns Renewal result
 */
export async function renewSession() {
  const supabase = await createClient();
  
  try {
    const { data, error } = await supabase.auth.refreshSession();
    
    if (error || !data.session) {
      return {
        success: false,
        error: error?.message || 'Failed to refresh session'
      };
    }
    
    return {
      success: true,
      session: data.session
    };
  } catch (error) {
    console.error('Session renewal error:', error);
    return {
      success: false,
      error: 'Session renewal failed'
    };
  }
}

/**
 * Invalidate the current session and clear cookies
 * @returns Invalidation result
 */
export async function invalidateSession() {
  const supabase = await createClient();
  
  try {
    // Sign out from Supabase
    const { error } = await supabase.auth.signOut();
    
    if (error) {
      console.error('Supabase signout error:', error);
    }
    
    // Clear session-related cookies
    const cookieStore = await cookies();
    const sessionCookies = [
      'sb-access-token',
      'sb-refresh-token',
      'supabase-auth-token',
      'supabase.auth.token'
    ];
    
    sessionCookies.forEach(cookieName => {
      try {
        cookieStore.delete(cookieName);
      } catch (error) {
        // Cookie might not exist, ignore error
      }
    });
    
    return { success: true };
  } catch (error) {
    console.error('Session invalidation error:', error);
    return {
      success: false,
      error: 'Failed to invalidate session'
    };
  }
}

/**
 * Check if user needs to re-authenticate for sensitive operations
 * @param lastAuthTime - Timestamp of last authentication
 * @param sensitiveThreshold - Time threshold for sensitive operations (in seconds)
 * @returns Whether re-authentication is required
 */
export function requiresReauth(lastAuthTime: number, sensitiveThreshold: number = 15 * 60): boolean {
  const now = Math.floor(Date.now() / 1000);
  return (now - lastAuthTime) > sensitiveThreshold;
}

/**
 * Middleware helper for session validation
 * @param config - Session configuration
 * @returns Session validation middleware
 */
export async function sessionMiddleware(config: SessionConfig = DEFAULT_SESSION_CONFIG) {
  const validation = await validateSession(config);
  
  if (!validation.valid) {
    redirect('/login?reason=session_expired');
  }
  
  return validation;
}

/**
 * Create a session activity tracker
 * @param userId - User ID to track
 * @param action - Action being performed
 * @returns Activity tracking result
 */
export async function trackSessionActivity(userId: string, action: string) {
  const supabase = await createClient();
  
  try {
    const { error } = await supabase
      .from('session_activities')
      .insert({
        user_id: userId,
        action,
        ip_address: await getClientIP(),
        user_agent: await getUserAgent(),
        created_at: new Date().toISOString()
      });
    
    if (error) {
      console.error('Session activity tracking error:', error);
      return { success: false, error: error.message };
    }
    
    return { success: true };
  } catch (error) {
    console.error('Session activity tracking error:', error);
    return { success: false, error: 'Failed to track session activity' };
  }
}

/**
 * Get recent session activities for a user
 * @param userId - User ID
 * @param limit - Number of activities to retrieve
 * @returns Recent session activities
 */
export async function getSessionActivities(userId: string, limit: number = 10) {
  const supabase = await createClient();
  
  try {
    const { data, error } = await supabase
      .from('session_activities')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit);
    
    if (error) {
      console.error('Session activities fetch error:', error);
      return { activities: [], error: error.message };
    }
    
    return { activities: data || [], error: null };
  } catch (error) {
    console.error('Session activities fetch error:', error);
    return { activities: [], error: 'Failed to fetch session activities' };
  }
}

/**
 * Detect suspicious session activity
 * @param userId - User ID to check
 * @returns Suspicious activity detection result
 */
export async function detectSuspiciousActivity(userId: string) {
  const supabase = await createClient();
  
  try {
    // Check for multiple IPs in recent activity
    const { data: recentActivities, error } = await supabase
      .from('session_activities')
      .select('ip_address, created_at')
      .eq('user_id', userId)
      .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())
      .order('created_at', { ascending: false });
    
    if (error) {
      console.error('Suspicious activity detection error:', error);
      return { suspicious: false, reasons: [], error: error.message };
    }
    
    const uniqueIPs = new Set(recentActivities?.map(a => a.ip_address) || []);
    const reasons: string[] = [];
    
    // Flag if more than 3 different IPs in 24 hours
    if (uniqueIPs.size > 3) {
      reasons.push(`Multiple IP addresses detected: ${uniqueIPs.size} different IPs`);
    }
    
    // Check for rapid successive logins
    const loginActivities = recentActivities?.filter(a => 
      a.created_at && new Date(a.created_at).getTime() > Date.now() - 60 * 60 * 1000
    ) || [];
    
    if (loginActivities.length > 10) {
      reasons.push(`High frequency activity: ${loginActivities.length} actions in the last hour`);
    }
    
    return {
      suspicious: reasons.length > 0,
      reasons,
      uniqueIPs: Array.from(uniqueIPs),
      error: null
    };
  } catch (error) {
    console.error('Suspicious activity detection error:', error);
    return { suspicious: false, reasons: [], error: 'Failed to detect suspicious activity' };
  }
}

/**
 * Helper function to get client IP
 */
async function getClientIP(): Promise<string> {
  try {
    const { headers } = await import('next/headers');
    const headersList = await headers();
    
    const xForwardedFor = headersList.get('x-forwarded-for');
    const xRealIP = headersList.get('x-real-ip');
    
    if (xForwardedFor) {
      return xForwardedFor.split(',')[0].trim();
    }
    
    if (xRealIP) {
      return xRealIP;
    }
    
    return 'unknown';
  } catch (error) {
    return 'unknown';
  }
}

/**
 * Helper function to get user agent
 */
async function getUserAgent(): Promise<string> {
  try {
    const { headers } = await import('next/headers');
    const headersList = await headers();
    
    return headersList.get('user-agent') || 'unknown';
  } catch (error) {
    return 'unknown';
  }
}

/**
 * Clean up old session activities
 * @param olderThanDays - Remove activities older than this many days
 * @returns Cleanup result
 */
export async function cleanupOldSessionActivities(olderThanDays: number = 30) {
  const supabase = await createClient();
  
  try {
    const cutoffDate = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
    
    const { count, error } = await supabase
      .from('session_activities')
      .delete()
      .lt('created_at', cutoffDate.toISOString());
    
    if (error) {
      console.error('Session activities cleanup error:', error);
      return { success: false, error: error.message, deletedCount: 0 };
    }
    
    return { success: true, deletedCount: count || 0, error: null };
  } catch (error) {
    console.error('Session activities cleanup error:', error);
    return { success: false, error: 'Failed to cleanup session activities', deletedCount: 0 };
  }
}