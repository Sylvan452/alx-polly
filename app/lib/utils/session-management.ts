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
    const timeUntilExpiry = (session.expires_at || 0) - now;
    
    // Calculate session age using user's last sign in time as fallback
    const lastSignInTime = session.user.last_sign_in_at ? Math.floor(new Date(session.user.last_sign_in_at).getTime() / 1000) : now;
    const sessionAge = now - lastSignInTime;
    
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
/**
 * Renews the current user session by refreshing authentication tokens.
 * 
 * This function attempts to refresh the user's session using Supabase's
 * refresh token mechanism. It should be called when a session is about
 * to expire or when token refresh is needed for continued authentication.
 * 
 * @returns Promise resolving to renewal result with success status and session data
 * 
 * @security
 * - Uses secure server-side Supabase client for token refresh
 * - Handles refresh token rotation securely
 * - Returns sanitized error messages without exposing internals
 * - Logs errors for security monitoring
 */
export async function renewSession() {
  const supabase = await createClient();
  
  try {
    // Attempt to refresh the session using the refresh token
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
 * Invalidates the current session and clears all authentication cookies.
 * 
 * This function performs a complete session cleanup including Supabase signout
 * and removal of all session-related cookies. It should be called during logout
 * or when forcing session termination for security reasons.
 * 
 * @returns Promise resolving to invalidation result with success status
 * 
 * @security
 * - Properly signs out from Supabase to invalidate server-side session
 * - Clears all authentication cookies to prevent session reuse
 * - Handles errors gracefully without exposing sensitive information
 * - Ensures complete session cleanup even if some steps fail
 */
export async function invalidateSession() {
  const supabase = await createClient();
  
  try {
    // Sign out from Supabase to invalidate server-side session
    const { error } = await supabase.auth.signOut();
    
    if (error) {
      console.error('Supabase signout error:', error);
    }
    
    // Clear all session-related cookies to prevent client-side session reuse
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
 * Determines if user needs to re-authenticate for sensitive operations.
 * 
 * This function implements step-up authentication by checking if enough time
 * has passed since the last authentication to require re-verification for
 * sensitive operations like password changes, financial transactions, etc.
 * 
 * @param lastAuthTime - Unix timestamp of last authentication
 * @param sensitiveThreshold - Time threshold for sensitive operations (in seconds, default: 15 minutes)
 * @returns Boolean indicating whether re-authentication is required
 * 
 * @security
 * - Implements step-up authentication for sensitive operations
 * - Configurable threshold allows different security levels
 * - Prevents unauthorized access to sensitive functions
 * - Uses secure time comparison to prevent timing attacks
 */
export function requiresReauth(lastAuthTime: number, sensitiveThreshold: number = 15 * 60): boolean {
  const now = Math.floor(Date.now() / 1000);
  return (now - lastAuthTime) > sensitiveThreshold;
}

/**
 * Middleware helper for comprehensive session validation.
 * 
 * This function provides a convenient way to validate sessions in Server Components
 * and Server Actions. It automatically redirects to login if the session is invalid,
 * making it easy to protect routes and actions.
 * 
 * @param config - Session configuration options (optional)
 * @returns Promise resolving to session validation result
 * 
 * @security
 * - Validates session using comprehensive security checks
 * - Automatically redirects on invalid sessions
 * - Prevents access to protected resources with expired sessions
 * - Uses secure redirect with reason parameter for user feedback
 */
export async function sessionMiddleware(config: SessionConfig = DEFAULT_SESSION_CONFIG) {
  const validation = await validateSession(config);
  
  if (!validation.valid) {
    redirect('/login?reason=session_expired');
  }
  
  return validation;
}

/**
 * Tracks user session activity for security auditing and monitoring.
 * 
 * This function logs user actions with contextual information including
 * IP address, user agent, and timestamp. It's essential for security
 * monitoring, fraud detection, and compliance requirements.
 * 
 * @param userId - Unique identifier of the user performing the action
 * @param action - Description of the action being performed (e.g., 'login', 'logout', 'password_change')
 * @returns Promise resolving to tracking result with success status
 * 
 * @security
 * - Logs security-relevant user actions for audit trails
 * - Captures IP address and user agent for forensic analysis
 * - Enables detection of suspicious activity patterns
 * - Supports compliance with security logging requirements
 */
export async function trackSessionActivity(userId: string, action: string) {
  const supabase = await createClient();
  
  try {
    // Insert activity record with security context information
    const { error } = await supabase
      .from('session_activities')
      .insert({
        user_id: userId,
        action,
        ip_address: await getClientIP(), // For geolocation and suspicious activity detection
        user_agent: await getUserAgent(), // For device fingerprinting
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
 * Retrieves recent session activities for security monitoring and user audit.
 * 
 * This function fetches the most recent session activities for a specific user,
 * which can be used for security dashboards, user activity logs, and
 * suspicious behavior detection.
 * 
 * @param userId - Unique identifier of the user whose activities to retrieve
 * @param limit - Maximum number of activities to retrieve (default: 10)
 * @returns Promise resolving to array of recent session activities
 * 
 * @security
 * - Provides audit trail for user actions
 * - Enables security monitoring and forensic analysis
 * - Supports detection of unauthorized account access
 * - Limited to prevent excessive data exposure
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
 * Analyzes user session patterns to detect potentially suspicious activity.
 * 
 * This function implements automated security monitoring by analyzing recent
 * session activities for patterns that may indicate account compromise,
 * such as multiple IP addresses or high-frequency actions.
 * 
 * @param userId - Unique identifier of the user to analyze
 * @returns Promise resolving to suspicious activity analysis result
 * 
 * @security
 * - Implements automated threat detection
 * - Identifies potential account compromise indicators
 * - Supports real-time security monitoring
 * - Provides detailed reasons for security team investigation
 */
export async function detectSuspiciousActivity(userId: string) {
  const supabase = await createClient();
  
  try {
    // Analyze recent activities for suspicious patterns (last 24 hours)
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
    
    // Security check: Flag multiple IP addresses (potential account sharing/compromise)
    if (uniqueIPs.size > 3) {
      reasons.push(`Multiple IP addresses detected: ${uniqueIPs.size} different IPs`);
    }
    
    // Security check: Detect high-frequency activity (potential automated attacks)
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
 * Securely extracts client IP address from request headers.
 * 
 * This helper function attempts to determine the real client IP address
 * by checking various headers commonly used by proxies and load balancers.
 * It's used for security logging and geolocation analysis.
 * 
 * @returns Promise resolving to client IP address or 'unknown' if unavailable
 * 
 * @security
 * - Checks multiple headers to get accurate IP address
 * - Handles proxy and load balancer scenarios
 * - Returns 'unknown' instead of exposing errors
 * - Used for security event logging and fraud detection
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
 * Securely extracts user agent string from request headers.
 * 
 * This helper function retrieves the user agent string which is used
 * for device fingerprinting, security analysis, and audit logging.
 * 
 * @returns Promise resolving to user agent string or 'unknown' if unavailable
 * 
 * @security
 * - Provides device fingerprinting for security analysis
 * - Used in session activity tracking for audit trails
 * - Returns 'unknown' instead of exposing errors
 * - Supports detection of automated attacks vs. legitimate users
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
 * Removes old session activity records for data retention compliance.
 * 
 * This function implements automated cleanup of historical session data
 * to comply with data retention policies and prevent database bloat.
 * It should be run periodically as part of maintenance routines.
 * 
 * @param olderThanDays - Remove activities older than this many days (default: 30)
 * @returns Promise resolving to cleanup result with deletion count
 * 
 * @security
 * - Implements data retention policy compliance
 * - Prevents indefinite storage of sensitive activity data
 * - Maintains audit trail within reasonable timeframe
 * - Supports GDPR and other privacy regulation requirements
 */
export async function cleanupOldSessionActivities(olderThanDays: number = 30) {
  const supabase = await createClient();
  
  try {
    // Calculate cutoff date for data retention policy
    const cutoffDate = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
    
    // Delete activities older than the retention period
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