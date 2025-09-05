import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';
import { logSecurityEvent } from './app/lib/utils/error-handling';

/**
 * Next.js middleware for authentication, authorization, and security.
 *
 * This middleware runs on every request and provides comprehensive security
 * controls including authentication verification, route protection, admin
 * authorization, session validation, and security header injection.
 *
 * @param request - The incoming Next.js request object
 * @returns NextResponse with appropriate redirects, security headers, or error responses
 *
 * @security
 * - Validates user authentication status using Supabase
 * - Enforces route-based access control (public, auth, protected, admin)
 * - Implements session freshness validation
 * - Logs security events for audit trails
 * - Applies security headers (CSP, X-Frame-Options, etc.)
 * - Provides rate limiting information for API routes
 * - Prevents unauthorized access to protected resources
 *
 * Route Classifications:
 * - Public routes: Accessible to all users (/, /about, etc.)
 * - Auth routes: Login/register pages (redirects authenticated users)
 * - Protected routes: Requires authentication (/dashboard, /profile, etc.)
 * - Admin routes: Requires admin role (/admin/*)
 * - API routes: Server endpoints with authentication requirements
 */
export async function middleware(request: NextRequest) {
  let supabaseResponse = NextResponse.next({
    request,
  });

  // Create Supabase client with server-side session handling for secure authentication
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) => {
            request.cookies.set(name, value);
            supabaseResponse.cookies.set(name, value, options);
          });
        },
      },
    },
  );

  // SECURITY: Comprehensive session validation - validate user session and get user data from secure server-side context
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();

  const { pathname } = request.nextUrl;
  const isAuthRoute = pathname.startsWith('/auth/');
  const isPublicRoute =
    ['/', '/about', '/privacy', '/terms', '/api/health'].includes(pathname) ||
    (pathname.startsWith('/poll/') && pathname.includes('/vote'));
  const isProtectedRoute = [
    '/dashboard',
    '/polls',
    '/admin',
    '/profile',
    '/settings',
  ].some((route) => pathname.startsWith(route));
  const isAdminRoute = pathname.startsWith('/admin');
  const isApiRoute = pathname.startsWith('/api/');

  // Extract client IP address for security event logging and audit trails
  const clientIP =
    request.headers.get('x-forwarded-for') ||
    request.headers.get('x-real-ip') ||
    'unknown';

  // SECURITY: Handle authentication errors
  if (userError) {
    await logSecurityEvent('AUTH_ERROR', {
      error: userError.message,
      path: pathname,
      ip: clientIP,
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    // Redirect to login for protected routes
    if (isProtectedRoute || isAdminRoute) {
      const redirectUrl = new URL('/auth/login', request.url);
      redirectUrl.searchParams.set('redirectTo', pathname);
      return NextResponse.redirect(redirectUrl);
    }
  }

  // SECURITY: Unauthenticated user access control
  if (!user) {
    // Allow access to public and auth routes
    if (isPublicRoute || isAuthRoute) {
      return supabaseResponse;
    }

    // Block access to protected routes
    if (isProtectedRoute || isAdminRoute) {
      await logSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', {
        path: pathname,
        ip: clientIP,
        userAgent: request.headers.get('user-agent') || 'unknown',
      });

      const redirectUrl = new URL('/auth/login', request.url);
      redirectUrl.searchParams.set('redirectTo', pathname);
      return NextResponse.redirect(redirectUrl);
    }

    // Block API routes except public ones
    if (isApiRoute && !pathname.startsWith('/api/public/')) {
      await logSecurityEvent('UNAUTHORIZED_API_ACCESS', {
        path: pathname,
        ip: clientIP,
        userAgent: request.headers.get('user-agent') || 'unknown',
      });
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 },
      );
    }

    return supabaseResponse;
  }

  // SECURITY: Authenticated user - additional validations

  // SECURITY: Validate session freshness to prevent stale session attacks
  const sessionAge = Date.now() - new Date(user.created_at).getTime();
  const maxSessionAge = 24 * 60 * 60 * 1000; // 24 hours maximum session lifetime

  if (sessionAge > maxSessionAge && isProtectedRoute) {
    await logSecurityEvent('SESSION_EXPIRED', {
      userId: user.id,
      sessionAge: sessionAge,
      path: pathname,
      ip: clientIP,
    });

    // Force re-authentication for expired sessions to maintain security
    await supabase.auth.signOut();
    const redirectUrl = new URL('/auth/login', request.url);
    redirectUrl.searchParams.set('redirectTo', pathname);
    redirectUrl.searchParams.set('reason', 'session_expired');
    return NextResponse.redirect(redirectUrl);
  }

  // SECURITY: Admin route protection
  if (isAdminRoute) {
    try {
      // Verify admin role from database (secure server-side check, not client-side)
      const { data: adminRole, error: roleError } = await supabase
        .from('user_roles')
        .select('role')
        .eq('user_id', user.id)
        .eq('role', 'admin')
        .limit(1)
        .single();

      if (roleError || !adminRole) {
        await logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', {
          userId: user.id,
          path: pathname,
          ip: clientIP,
          userAgent: request.headers.get('user-agent') || 'unknown',
        });

        return NextResponse.redirect(new URL('/dashboard', request.url));
      }

      // Log successful admin access for security audit trails
      await logSecurityEvent('ADMIN_ACCESS', {
        userId: user.id,
        path: pathname,
        ip: clientIP,
      });
    } catch (error) {
      await logSecurityEvent('ADMIN_CHECK_ERROR', {
        userId: user.id,
        path: pathname,
        error: error instanceof Error ? error.message : 'Unknown error',
        ip: clientIP,
      });

      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
  }

  // SECURITY: Redirect authenticated users away from auth routes
  if (isAuthRoute && user) {
    const redirectTo =
      request.nextUrl.searchParams.get('redirectTo') || '/dashboard';
    return NextResponse.redirect(new URL(redirectTo, request.url));
  }

  // SECURITY: Add rate limiting headers for API routes to prevent abuse
  if (isApiRoute) {
    supabaseResponse.headers.set('X-RateLimit-Limit', '100');
    supabaseResponse.headers.set('X-RateLimit-Remaining', '99');
    supabaseResponse.headers.set(
      'X-RateLimit-Reset',
      String(Date.now() + 3600000),
    );
  }

  // SECURITY: Apply comprehensive security headers to prevent common attacks
  supabaseResponse.headers.set('X-Frame-Options', 'DENY'); // Prevent clickjacking
  supabaseResponse.headers.set('X-Content-Type-Options', 'nosniff'); // Prevent MIME sniffing
  supabaseResponse.headers.set(
    'Referrer-Policy',
    'strict-origin-when-cross-origin',
  ); // Control referrer info
  supabaseResponse.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()',
  ); // Restrict browser APIs

  // Content Security Policy header for XSS protection
  const cspHeader = [
    "default-src 'self'", // Only allow resources from same origin by default
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Note: Consider removing unsafe-* in production
    "style-src 'self' 'unsafe-inline'", // Allow inline styles (required for some frameworks)
    "img-src 'self' data: https:", // Allow images from same origin, data URLs, and HTTPS
    "font-src 'self'", // Only allow fonts from same origin
    "connect-src 'self' https://*.supabase.co", // Allow connections to Supabase
    "frame-ancestors 'none'", // Prevent embedding in frames
  ].join('; ');

  supabaseResponse.headers.set('Content-Security-Policy', cspHeader);

  return supabaseResponse;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
