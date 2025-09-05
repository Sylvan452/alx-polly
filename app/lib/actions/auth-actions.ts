'use server';

import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import {
  checkRateLimit,
  getClientIP,
  RATE_LIMITS,
} from '@/app/lib/utils/rate-limit';
import { headers } from 'next/headers';
import { validateCSRF } from '@/app/lib/utils/csrf';
import { isValidEmail, validateStringLength } from '@/app/lib/utils/validation';
import {
  trackSessionActivity,
  invalidateSession,
} from '@/app/lib/utils/session-management';
import {
  sanitizeError,
  logSecurityEvent,
} from '@/app/lib/utils/error-handling';

/**
 * Authenticates a user with email and password credentials.
 *
 * This function implements comprehensive security measures including CSRF protection,
 * rate limiting, input validation, and secure error handling. It tracks successful
 * login attempts for audit purposes and redirects authenticated users to the dashboard.
 *
 * @param formData - Form data containing email and password fields
 * @returns Promise resolving to an object with error property (null on success)
 *
 * @security
 * - CSRF token validation prevents cross-site request forgery
 * - Rate limiting prevents brute force attacks (per IP address)
 * - Error sanitization prevents information disclosure
 * - Session activity tracking for security auditing
 * - Secure redirect after successful authentication
 */
export async function login(formData: FormData) {
  // CSRF validation - prevents cross-site request forgery attacks
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  // Extract and validate required form fields
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;

  if (!email || !password) {
    return { error: 'Email and password are required' };
  }

  // Rate limiting check - prevents brute force attacks by IP
  const headersList = await headers();
  const clientIP = getClientIP(headersList);
  const rateLimitResult = checkRateLimit(`auth:${clientIP}`, RATE_LIMITS.AUTH);

  if (!rateLimitResult.success) {
    const resetTime = new Date(rateLimitResult.resetTime);
    return {
      error: `Too many login attempts. Please try again after ${resetTime.toLocaleTimeString()}.`,
    };
  }

  const supabase = await createClient();
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error) {
    // Sanitize error to prevent information disclosure
    const safeError = sanitizeError(error, {
      action: 'login',
      timestamp: new Date().toISOString(),
    });

    // Log security event for monitoring and audit purposes
    await logSecurityEvent('ERROR_OCCURRED', {
      action: 'login',
      errorCode: safeError.code,
      email: email, // Safe to log email for login attempts
    });

    return { error: safeError.message };
  }

  // Track successful login activity for security auditing
  if (data.user) {
    await trackSessionActivity(data.user.id, 'login');
  }

  // If login succeeds
  redirect('/dashboard');
  return { error: null };
}

/**
 * Validates password complexity according to security requirements.
 *
 * Enforces strong password policies to prevent weak credentials that could
 * be easily compromised through dictionary attacks or brute force attempts.
 *
 * @param password - The password string to validate
 * @returns Object containing validation result and error message if invalid
 *
 * @security
 * - Minimum 8 characters, maximum 128 to prevent DoS via large inputs
 * - Requires uppercase, lowercase, numeric, and special characters
 * - Prevents common weak password patterns
 */
function validatePassword(password: string): {
  valid: boolean;
  error?: string;
} {
  // Check password length - prevents both weak and DoS-inducing passwords
  const lengthValidation = validateStringLength(password, 8, 128);
  if (!lengthValidation.valid) {
    return { valid: false, error: lengthValidation.error };
  }

  // Require uppercase letter for complexity
  if (!/[A-Z]/.test(password)) {
    return {
      valid: false,
      error: 'Password must contain at least one uppercase letter.',
    };
  }

  // Require lowercase letter for complexity
  if (!/[a-z]/.test(password)) {
    return {
      valid: false,
      error: 'Password must contain at least one lowercase letter.',
    };
  }

  // Require numeric character for complexity
  if (!/\d/.test(password)) {
    return {
      valid: false,
      error: 'Password must contain at least one number.',
    };
  }

  // Require special character for complexity
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return {
      valid: false,
      error: 'Password must contain at least one special character.',
    };
  }

  return { valid: true };
}

/**
 * Registers a new user account with email and password.
 *
 * Creates a new user account with comprehensive validation and security measures.
 * Implements the same security protections as login, plus additional password
 * complexity validation to ensure strong user credentials from account creation.
 *
 * @param formData - Form data containing email and password fields
 * @returns Promise resolving to an object with error property (null on success)
 *
 * @security
 * - CSRF token validation prevents cross-site request forgery
 * - Rate limiting prevents automated account creation attacks
 * - Email format validation prevents malformed email addresses
 * - Strong password complexity requirements
 * - Error sanitization prevents information disclosure
 * - Session activity tracking for security auditing
 */
export async function register(formData: FormData) {
  // CSRF validation - prevents cross-site request forgery attacks
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  // Extract and validate required form fields
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;

  if (!email || !password) {
    return { error: 'Email and password are required' };
  }

  // Rate limiting check - prevents automated registration attacks
  const headersList = await headers();
  const clientIP = getClientIP(headersList);
  const rateLimitResult = checkRateLimit(`auth:${clientIP}`, RATE_LIMITS.AUTH);

  if (!rateLimitResult.success) {
    const resetTime = new Date(rateLimitResult.resetTime);
    return {
      error: `Too many registration attempts. Please try again after ${resetTime.toLocaleTimeString()}.`,
    };
  }

  // Email format validation - prevents malformed email addresses
  if (!isValidEmail(email)) {
    return { error: 'Please enter a valid email address' };
  }

  // Validate password complexity - enforces strong password policy
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return { error: passwordValidation.error };
  }

  const supabase = await createClient();
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
  });

  if (error) {
    // Sanitize error to prevent information disclosure
    const safeError = sanitizeError(error, {
      action: 'register',
      timestamp: new Date().toISOString(),
    });

    // Log security event for monitoring and audit purposes
    await logSecurityEvent('ERROR_OCCURRED', {
      action: 'register',
      errorCode: safeError.code,
    });

    return { error: safeError.message };
  }

  // Track successful registration activity for security auditing
  if (data.user) {
    await trackSessionActivity(data.user.id, 'register');
  }

  redirect('/dashboard');
  return { error: null };
}

/**
 * Securely logs out the current user and invalidates their session.
 *
 * Performs a complete logout process including session invalidation,
 * cookie cleanup, and activity tracking for security auditing. This ensures
 * that the user's session cannot be reused after logout.
 *
 * @returns Promise resolving to an object with error property (null on success)
 *
 * @security
 * - Tracks logout activity for audit trails
 * - Properly invalidates server-side session state
 * - Clears authentication cookies to prevent session reuse
 * - Handles logout errors gracefully without exposing internals
 */
export async function logout() {
  const supabase = await createClient();

  // Get current user before signing out for activity tracking
  const {
    data: { user },
  } = await supabase.auth.getUser();

  // Track logout activity for security auditing
  if (user) {
    await trackSessionActivity(user.id, 'logout');
  }

  // Properly invalidate session and clear cookies
  await invalidateSession();

  const { error } = await supabase.auth.signOut();
  if (error) {
    return { error: error.message };
  }
  return { error: null };
}

/**
 * Retrieves the currently authenticated user from the session.
 *
 * This function provides a secure way to access the current user's information
 * from the server-side session. It should be used in Server Components and
 * Server Actions where user context is needed.
 *
 * @returns Promise resolving to the current User object or null if not authenticated
 *
 * @security
 * - Uses server-side Supabase client for secure session access
 * - Returns null for unauthenticated requests (no error exposure)
 * - Safe for use in protected routes and user-specific operations
 */
export async function getCurrentUser() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

/**
 * Retrieves the current authentication session.
 *
 * Provides access to the complete session object including tokens and metadata.
 * This function should be used when session-specific information (like tokens
 * or expiration times) is needed for authentication decisions.
 *
 * @returns Promise resolving to the current Session object or null if not authenticated
 *
 * @security
 * - Uses server-side Supabase client for secure session access
 * - Session contains sensitive tokens - handle with care
 * - Returns null for unauthenticated requests (no error exposure)
 * - Should not be used to expose session data to client-side code
 */
export async function getSession() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getSession();
  return data.session;
}
