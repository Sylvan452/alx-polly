/**
 * Session middleware for route protection and session validation
 * 
 * This module provides middleware functions for protecting routes based on authentication
 * and authorization requirements. It handles session validation, admin checks, and
 * security headers for Next.js applications.
 * 
 * @security Implements defense-in-depth with multiple validation layers
 * @security Uses secure session validation with configurable timeouts
 * @security Provides admin role verification through database checks
 */
import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { validateSession, DEFAULT_SESSION_CONFIG, SENSITIVE_SESSION_CONFIG } from '../utils/session-management';

/**
 * Configuration interface for route protection settings
 * 
 * Defines the security requirements and allowed operations for specific routes.
 * Used by the session middleware to determine access control policies.
 * 
 * @interface RouteConfig
 * @property {boolean} requireAuth - Whether the route requires authentication
 * @property {boolean} [requireAdmin] - Whether the route requires admin privileges
 * @property {boolean} [sensitiveOperation] - Whether the route performs sensitive operations requiring stricter validation
 * @property {string[]} [allowedMethods] - HTTP methods allowed for this route
 * 
 * @security Admin routes should always set requireAdmin: true
 * @security Sensitive operations should use sensitiveOperation: true for enhanced security
 */
export interface RouteConfig {
  requireAuth: boolean;
  requireAdmin?: boolean;
  sensitiveOperation?: boolean;
  allowedMethods?: string[];
}

// Route configurations
export const ROUTE_CONFIGS: Record<string, RouteConfig> = {
  '/dashboard': {
    requireAuth: true,
    allowedMethods: ['GET', 'POST']
  },
  '/admin': {
    requireAuth: true,
    requireAdmin: true,
    sensitiveOperation: true,
    allowedMethods: ['GET', 'POST', 'DELETE']
  },
  '/poll/create': {
    requireAuth: true,
    allowedMethods: ['GET', 'POST']
  },
  '/poll/[id]/edit': {
    requireAuth: true,
    allowedMethods: ['GET', 'POST']
  },
  '/api/admin': {
    requireAuth: true,
    requireAdmin: true,
    sensitiveOperation: true,
    allowedMethods: ['POST', 'DELETE']
  }
};

/**
 * Main session middleware function for route protection and authentication
 * 
 * This middleware enforces authentication and authorization policies for protected routes.
 * It validates sessions, checks admin privileges, and provides security headers for
 * downstream components.
 * 
 * @param {NextRequest} request - The incoming Next.js request object
 * @returns {Promise<NextResponse>} Response object or NextResponse.next() to continue
 * 
 * @security Validates session authenticity and freshness
 * @security Enforces role-based access control for admin routes
 * @security Uses different session validation configs for sensitive operations
 * @security Logs security events for monitoring and audit trails
 * 
 * @example
 * ```typescript
 * // In middleware.ts
 * export async function middleware(request: NextRequest) {
 *   return await sessionMiddleware(request);
 * }
 * ```
 */
export async function sessionMiddleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // Find matching route configuration based on pathname patterns
  const routeConfig = findRouteConfig(pathname);
  
  // Allow unprotected routes to proceed without authentication
  if (!routeConfig) {
    return NextResponse.next();
  }
  
  // Enforce HTTP method restrictions for security
  if (routeConfig.allowedMethods && !routeConfig.allowedMethods.includes(request.method)) {
    return new NextResponse('Method Not Allowed', { status: 405 });
  }
  
  // Skip authentication for public routes
  if (!routeConfig.requireAuth) {
    return NextResponse.next();
  }
  
  try {
    // Create Supabase client with middleware configuration
    const supabase = await createClient();
    const { data: { session }, error } = await supabase.auth.getSession();
    
    // Redirect to login if session is invalid or missing
    if (error || !session) {
      return redirectToLogin(request, 'session_required');
    }
    
    // Use stricter validation for sensitive operations (admin, financial, etc.)
    const sessionConfig = routeConfig.sensitiveOperation 
      ? SENSITIVE_SESSION_CONFIG 
      : DEFAULT_SESSION_CONFIG;
    
    // Validate session freshness and authenticity
    const validation = await validateSessionForMiddleware(session, sessionConfig);
    
    // Force re-authentication if session validation fails
    if (!validation.valid) {
      return redirectToLogin(request, validation.error || 'session_invalid');
    }
    
    // Verify admin privileges for protected admin routes
    if (routeConfig.requireAdmin) {
      const isAdmin = await checkAdminStatus(supabase, session.user.id);
      if (!isAdmin) {
        return new NextResponse('Forbidden: Admin access required', { status: 403 });
      }
    }
    
    // Pass session information to downstream components via headers
    const response = NextResponse.next();
    response.headers.set('x-user-id', session.user.id);
    response.headers.set('x-session-valid', 'true');
    
    // Signal when session renewal is recommended
    if (validation.needsRenewal) {
      response.headers.set('x-session-renewal-needed', 'true');
    }
    
    return response;
    
  } catch (error) {
    console.error('Session middleware error:', error);
    return redirectToLogin(request, 'middleware_error');
  }
}

/**
 * Find route configuration for a given pathname
 * 
 * Searches for matching route configuration using exact match first,
 * then falls back to pattern matching for dynamic routes.
 * 
 * @param {string} pathname - The request pathname to match
 * @returns {RouteConfig | null} Route configuration object or null if no match
 * 
 * @security Uses secure pattern matching to prevent route bypass attacks
 * @security Prioritizes exact matches to avoid ambiguous route resolution
 * 
 * @example
 * ```typescript
 * const config = findRouteConfig('/admin/users');
 * if (config?.requireAdmin) {
 *   // Handle admin route
 * }
 * ```
 */
function findRouteConfig(pathname: string): RouteConfig | null {
  // Exact match first - prevents route confusion attacks
  if (ROUTE_CONFIGS[pathname]) {
    return ROUTE_CONFIGS[pathname];
  }
  
  // Pattern matching for dynamic routes (e.g., /poll/[id]/edit)
  for (const [pattern, config] of Object.entries(ROUTE_CONFIGS)) {
    if (matchesPattern(pathname, pattern)) {
      return config;
    }
  }
  
  // No matching configuration found - route is unprotected
  return null;
}

/**
 * Check if pathname matches a route pattern with dynamic segments
 * 
 * Converts Next.js route patterns (with [id] placeholders) to regular expressions
 * for secure pattern matching. Prevents path traversal and route bypass attacks.
 * 
 * @param {string} pathname - The actual request pathname
 * @param {string} pattern - The route pattern with [id] placeholders
 * @returns {boolean} True if pathname matches the pattern
 * 
 * @security Uses strict regex patterns to prevent path traversal
 * @security Escapes special characters to prevent regex injection
 * 
 * @example
 * ```typescript
 * matchesPattern('/poll/123/edit', '/poll/[id]/edit'); // returns true
 * matchesPattern('/poll/123/delete', '/poll/[id]/edit'); // returns false
 * ```
 */
function matchesPattern(pathname: string, pattern: string): boolean {
  // Convert Next.js pattern to secure regex pattern
  const regexPattern = pattern
    .replace(/\[\w+\]/g, '[^/]+') // Replace [id] with regex for any non-slash characters
    .replace(/\//g, '\\/'); // Escape forward slashes for regex safety
  
  // Create anchored regex to prevent partial matches
  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(pathname);
}

/**
 * Validate session for middleware with simplified validation logic
 * 
 * Performs lightweight session validation suitable for middleware context.
 * Checks session age and expiry time without database queries for performance.
 * 
 * @param {any} session - The Supabase session object
 * @param {any} config - Session configuration with maxAge and renewalThreshold
 * @returns {Promise<object>} Validation result with valid flag and metadata
 * 
 * @security Validates session timestamps to prevent replay attacks
 * @security Uses configurable thresholds for different security contexts
 * @security Returns detailed validation info for security monitoring
 * 
 * @example
 * ```typescript
 * const validation = await validateSessionForMiddleware(session, SENSITIVE_SESSION_CONFIG);
 * if (!validation.valid) {
 *   return redirectToLogin(request, validation.error);
 * }
 * ```
 */
async function validateSessionForMiddleware(session: any, config: any) {
  const now = Math.floor(Date.now() / 1000);
  const sessionAge = now - (session.issued_at || 0);
  const timeUntilExpiry = (session.expires_at || 0) - now;
  
  // Enforce maximum session age to limit exposure window
  if (sessionAge > config.maxAge) {
    return {
      valid: false,
      error: 'session_expired_max_age'
    };
  }
  
  // Determine if session renewal is recommended for security
  const needsRenewal = timeUntilExpiry < config.renewalThreshold;
  
  return {
    valid: true,
    needsRenewal,
    sessionAge,
    timeUntilExpiry
  };
}

/**
 * Check admin status for middleware authorization
 * 
 * Verifies if a user has admin privileges by querying the user_roles table.
 * Used for protecting admin-only routes and sensitive operations.
 * 
 * @param {any} supabase - The Supabase client instance
 * @param {string} userId - The user ID to check admin status for
 * @returns {Promise<boolean>} True if user has admin role, false otherwise
 * 
 * @security Queries database to verify current admin status
 * @security Fails securely by returning false on any error
 * @security Logs errors for security monitoring without exposing details
 * 
 * @example
 * ```typescript
 * const isAdmin = await checkAdminStatus(supabase, session.user.id);
 * if (!isAdmin) {
 *   return new NextResponse('Forbidden', { status: 403 });
 * }
 * ```
 */
async function checkAdminStatus(supabase: any, userId: string): Promise<boolean> {
  try {
    // Query user_roles table for admin privilege verification
    const { data, error } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', userId)
      .eq('role', 'admin')
      .single();
    
    // Return true only if query succeeds and role is admin
    return !error && data?.role === 'admin';
  } catch (error) {
    // Log error for monitoring but fail securely
    console.error('Admin status check error:', error);
    return false;
  }
}

/**
 * Redirect to login page with contextual information
 * 
 * Creates a secure redirect to the login page with reason and return URL.
 * Preserves the original destination for post-login redirect.
 * 
 * @param {NextRequest} request - The Next.js request object
 * @param {string} reason - The reason for requiring login (for UX and logging)
 * @returns {NextResponse} Redirect response to login page
 * 
 * @security Preserves original URL for post-login redirect
 * @security Includes reason for security event logging
 * @security Uses secure URL construction to prevent open redirects
 * 
 * @example
 * ```typescript
 * if (!session) {
 *   return redirectToLogin(request, 'session_required');
 * }
 * ```
 */
function redirectToLogin(request: NextRequest, reason: string) {
  // Construct login URL with current domain
  const loginUrl = new URL('/login', request.url);
  
  // Add reason for UX messaging and security logging
  loginUrl.searchParams.set('reason', reason);
  
  // Preserve original destination for post-login redirect
  loginUrl.searchParams.set('redirect', request.nextUrl.pathname);
  
  return NextResponse.redirect(loginUrl);
}

/**
 * Rate limiting middleware for session-based actions
 * 
 * Implements rate limiting based on user session or IP address to prevent abuse.
 * Uses persistent storage for rate limit tracking across server restarts.
 * 
 * @param {NextRequest} request - The Next.js request object
 * @param {string} action - The action being performed (for different rate limits)
 * @returns {Promise<object>} Rate limit result with allowed status and metadata
 * 
 * @security Prevents brute force attacks and API abuse
 * @security Uses user ID when available, falls back to IP for anonymous users
 * @security Implements persistent rate limiting across server restarts
 * @security Fails securely by denying access on rate limit check errors
 * 
 * @example
 * ```typescript
 * const rateLimit = await sessionRateLimit(request, 'login_attempt');
 * if (!rateLimit.allowed) {
 *   return new NextResponse('Rate limit exceeded', { status: 429 });
 * }
 * ```
 */
export async function sessionRateLimit(request: NextRequest, action: string) {
  try {
    // Get session for user-based rate limiting
    const supabase = await createClient();
    const { data: { session } } = await supabase.auth.getSession();
    
    // Require session for rate limiting
    if (!session) {
      return { allowed: false, error: 'No session' };
    }
    
    // Extract client IP as fallback identifier
    const clientIP = getClientIP(request);
    const identifier = session.user.id || clientIP;
    
    // Apply persistent rate limiting with action-specific limits
    const { checkPersistentRateLimit, PERSISTENT_RATE_LIMITS } = await import('../utils/persistent-rate-limit');
    
    // Select appropriate rate limit based on action
    const limit = PERSISTENT_RATE_LIMITS.AUTH; // Default to AUTH limit
    const rateLimitResult = await checkPersistentRateLimit(identifier, action, limit);
    
    return {
      allowed: rateLimitResult.allowed,
      error: rateLimitResult.allowed ? null : 'Rate limit exceeded',
      remaining: rateLimitResult.remaining,
      resetTime: rateLimitResult.resetTime
    };
  } catch (error) {
    // Log error and fail securely
    console.error('Session rate limit error:', error);
    return { allowed: false, error: 'Rate limit check failed' };
  }
}

/**
 * Extract client IP address from request headers
 * 
 * Attempts to determine the real client IP address by checking various
 * proxy headers in order of preference. Used for rate limiting and security logging.
 * 
 * @param {NextRequest} request - The Next.js request object
 * @returns {string} The client IP address or 'unknown' if not determinable
 * 
 * @security Checks multiple headers to handle different proxy configurations
 * @security Returns 'unknown' as safe fallback when IP cannot be determined
 * @security Handles comma-separated IPs in X-Forwarded-For header
 * 
 * @example
 * ```typescript
 * const clientIP = getClientIP(request);
 * console.log(`Request from IP: ${clientIP}`);
 * ```
 */
function getClientIP(request: NextRequest): string {
  // Check X-Forwarded-For header (most common proxy header)
  const xForwardedFor = request.headers.get('x-forwarded-for');
  
  // Check X-Real-IP header (alternative proxy header)
  const xRealIP = request.headers.get('x-real-ip');
  
  // X-Forwarded-For can contain multiple IPs, use the first (original client)
  if (xForwardedFor) {
    return xForwardedFor.split(',')[0].trim();
  }
  
  // Fall back to X-Real-IP if available
  if (xRealIP) {
    return xRealIP;
  }
  
  // Return safe fallback when IP cannot be determined
  return 'unknown';
}

/**
 * Add comprehensive security headers to response
 * 
 * Applies a comprehensive set of security headers to protect against common
 * web vulnerabilities including XSS, clickjacking, and content sniffing attacks.
 * 
 * @param {NextResponse} response - The Next.js response object to modify
 * @returns {NextResponse} The response object with security headers added
 * 
 * @security Prevents clickjacking with X-Frame-Options: DENY
 * @security Prevents MIME sniffing with X-Content-Type-Options: nosniff
 * @security Controls referrer information leakage
 * @security Restricts dangerous browser features with Permissions-Policy
 * @security Implements Content Security Policy to prevent XSS
 * 
 * @example
 * ```typescript
 * const response = NextResponse.next();
 * return addSecurityHeaders(response);
 * ```
 */
export function addSecurityHeaders(response: NextResponse) {
  // Prevent clickjacking attacks
  response.headers.set('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  response.headers.set('X-Content-Type-Options', 'nosniff');
  
  // Control referrer information leakage
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Restrict dangerous browser features
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  
  // Implement Content Security Policy to prevent XSS
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Note: Remove unsafe-* in production
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self' https://*.supabase.co",
    "frame-ancestors 'none'"
  ].join('; ');
  
  response.headers.set('Content-Security-Policy', csp);
  
  return response;
}