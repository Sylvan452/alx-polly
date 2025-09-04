// Session middleware for route protection and session validation
import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/middleware';
import { validateSession, DEFAULT_SESSION_CONFIG, SENSITIVE_SESSION_CONFIG } from '@/lib/utils/session-management';

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
 * Session middleware for Next.js middleware
 * @param request - Next.js request object
 * @returns Response or null to continue
 */
export async function sessionMiddleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // Find matching route configuration
  const routeConfig = findRouteConfig(pathname);
  
  if (!routeConfig) {
    return NextResponse.next();
  }
  
  // Check if method is allowed
  if (routeConfig.allowedMethods && !routeConfig.allowedMethods.includes(request.method)) {
    return new NextResponse('Method Not Allowed', { status: 405 });
  }
  
  // Skip auth check for non-protected routes
  if (!routeConfig.requireAuth) {
    return NextResponse.next();
  }
  
  try {
    const supabase = createClient(request);
    const { data: { session }, error } = await supabase.auth.getSession();
    
    if (error || !session) {
      return redirectToLogin(request, 'session_required');
    }
    
    // Validate session with appropriate configuration
    const sessionConfig = routeConfig.sensitiveOperation 
      ? SENSITIVE_SESSION_CONFIG 
      : DEFAULT_SESSION_CONFIG;
    
    const validation = await validateSessionForMiddleware(session, sessionConfig);
    
    if (!validation.valid) {
      return redirectToLogin(request, validation.error || 'session_invalid');
    }
    
    // Check admin requirement
    if (routeConfig.requireAdmin) {
      const isAdmin = await checkAdminStatus(supabase, session.user.id);
      if (!isAdmin) {
        return new NextResponse('Forbidden: Admin access required', { status: 403 });
      }
    }
    
    // Add session info to headers for downstream use
    const response = NextResponse.next();
    response.headers.set('x-user-id', session.user.id);
    response.headers.set('x-session-valid', 'true');
    
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
 * @param pathname - Request pathname
 * @returns Route configuration or null
 */
function findRouteConfig(pathname: string): RouteConfig | null {
  // Exact match first
  if (ROUTE_CONFIGS[pathname]) {
    return ROUTE_CONFIGS[pathname];
  }
  
  // Pattern matching for dynamic routes
  for (const [pattern, config] of Object.entries(ROUTE_CONFIGS)) {
    if (matchesPattern(pathname, pattern)) {
      return config;
    }
  }
  
  return null;
}

/**
 * Check if pathname matches a route pattern
 * @param pathname - Request pathname
 * @param pattern - Route pattern with [id] placeholders
 * @returns Whether pathname matches pattern
 */
function matchesPattern(pathname: string, pattern: string): boolean {
  // Convert pattern to regex
  const regexPattern = pattern
    .replace(/\[\w+\]/g, '[^/]+') // Replace [id] with regex for any non-slash characters
    .replace(/\//g, '\\/'); // Escape forward slashes
  
  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(pathname);
}

/**
 * Validate session for middleware (simplified version)
 * @param session - Supabase session
 * @param config - Session configuration
 * @returns Validation result
 */
async function validateSessionForMiddleware(session: any, config: any) {
  const now = Math.floor(Date.now() / 1000);
  const sessionAge = now - (session.issued_at || 0);
  const timeUntilExpiry = (session.expires_at || 0) - now;
  
  // Check if session has exceeded max age
  if (sessionAge > config.maxAge) {
    return {
      valid: false,
      error: 'session_expired_max_age'
    };
  }
  
  // Check if session is close to expiry
  const needsRenewal = timeUntilExpiry < config.renewalThreshold;
  
  return {
    valid: true,
    needsRenewal,
    sessionAge,
    timeUntilExpiry
  };
}

/**
 * Check admin status for middleware
 * @param supabase - Supabase client
 * @param userId - User ID
 * @returns Whether user is admin
 */
async function checkAdminStatus(supabase: any, userId: string): Promise<boolean> {
  try {
    const { data, error } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', userId)
      .eq('role', 'admin')
      .single();
    
    return !error && data?.role === 'admin';
  } catch (error) {
    console.error('Admin status check error:', error);
    return false;
  }
}

/**
 * Redirect to login with reason
 * @param request - Next.js request
 * @param reason - Reason for redirect
 * @returns Redirect response
 */
function redirectToLogin(request: NextRequest, reason: string) {
  const loginUrl = new URL('/login', request.url);
  loginUrl.searchParams.set('reason', reason);
  loginUrl.searchParams.set('redirect', request.nextUrl.pathname);
  
  return NextResponse.redirect(loginUrl);
}

/**
 * Rate limiting middleware for session-based actions
 * @param request - Next.js request
 * @param action - Action being performed
 * @returns Rate limit check result
 */
export async function sessionRateLimit(request: NextRequest, action: string) {
  try {
    const supabase = createClient(request);
    const { data: { session } } = await supabase.auth.getSession();
    
    if (!session) {
      return { allowed: false, error: 'No session' };
    }
    
    // Get client IP for rate limiting
    const clientIP = getClientIP(request);
    const identifier = session.user.id || clientIP;
    
    // Check rate limit using persistent rate limiting
    const { checkPersistentRateLimit } = await import('@/lib/utils/persistent-rate-limit');
    const rateLimitResult = await checkPersistentRateLimit(identifier, action);
    
    return {
      allowed: rateLimitResult.allowed,
      error: rateLimitResult.allowed ? null : 'Rate limit exceeded',
      remaining: rateLimitResult.remaining,
      resetTime: rateLimitResult.resetTime
    };
  } catch (error) {
    console.error('Session rate limit error:', error);
    return { allowed: false, error: 'Rate limit check failed' };
  }
}

/**
 * Get client IP from request
 * @param request - Next.js request
 * @returns Client IP address
 */
function getClientIP(request: NextRequest): string {
  const xForwardedFor = request.headers.get('x-forwarded-for');
  const xRealIP = request.headers.get('x-real-ip');
  
  if (xForwardedFor) {
    return xForwardedFor.split(',')[0].trim();
  }
  
  if (xRealIP) {
    return xRealIP;
  }
  
  return 'unknown';
}

/**
 * Security headers middleware
 * @param response - Next.js response
 * @returns Response with security headers
 */
export function addSecurityHeaders(response: NextResponse) {
  // Add security headers
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  
  // Add CSP header
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self' https://*.supabase.co",
    "frame-ancestors 'none'"
  ].join('; ');
  
  response.headers.set('Content-Security-Policy', csp);
  
  return response;
}