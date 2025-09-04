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
import { trackSessionActivity, invalidateSession } from '@/lib/utils/session-management';
import { sanitizeError, logSecurityEvent } from '@/lib/utils/error-handling';

export async function login(formData: FormData) {
  // CSRF validation
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  // Extract form data
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;

  if (!email || !password) {
    return { error: 'Email and password are required' };
  }

  // Rate limiting check
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
    const safeError = sanitizeError(error, {
      action: 'login',
      timestamp: new Date().toISOString()
    });
    
    logSecurityEvent('ERROR_OCCURRED', {
      action: 'login',
      errorCode: safeError.code,
      email: email // Safe to log email for login attempts
    });
    
    return { error: safeError.message };
  }

  // Track successful login activity
  if (data.user) {
    await trackSessionActivity(data.user.id, 'login');
  }

  // If login succeeds
  redirect('/dashboard');
  return { error: null };
}

function validatePassword(password: string): { valid: boolean; error?: string } {
  // Check password length
  const lengthValidation = validateStringLength(password, 8, 128);
  if (!lengthValidation.valid) {
    return { valid: false, error: lengthValidation.error };
  }
  
  // Check for at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: "Password must contain at least one uppercase letter." };
  }
  
  // Check for at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: "Password must contain at least one lowercase letter." };
  }
  
  // Check for at least one number
  if (!/\d/.test(password)) {
    return { valid: false, error: "Password must contain at least one number." };
  }
  
  // Check for at least one special character
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return { valid: false, error: "Password must contain at least one special character." };
  }
  
  return { valid: true };
}

export async function register(formData: FormData) {
  // CSRF validation
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  // Extract form data
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;

  if (!email || !password) {
    return { error: 'Email and password are required' };
  }

  // Rate limiting check
  const headersList = await headers();
  const clientIP = getClientIP(headersList);
  const rateLimitResult = checkRateLimit(`auth:${clientIP}`, RATE_LIMITS.AUTH);

  if (!rateLimitResult.success) {
    const resetTime = new Date(rateLimitResult.resetTime);
    return {
      error: `Too many registration attempts. Please try again after ${resetTime.toLocaleTimeString()}.`,
    };
  }

  // Email format validation
  if (!isValidEmail(email)) {
    return { error: 'Please enter a valid email address' };
  }

  // Validate password complexity
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
    const safeError = sanitizeError(error, {
      action: 'register',
      timestamp: new Date().toISOString()
    });
    
    logSecurityEvent('ERROR_OCCURRED', {
      action: 'register',
      errorCode: safeError.code
    });
    
    return { error: safeError.message };
  }

  // Track successful registration activity
  if (data.user) {
    await trackSessionActivity(data.user.id, 'register');
  }

  redirect('/dashboard');
  return { error: null };
}

export async function logout() {
  const supabase = await createClient();
  
  // Get current user before signing out
  const { data: { user } } = await supabase.auth.getUser();
  
  // Track logout activity
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

export async function getCurrentUser() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

export async function getSession() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getSession();
  return data.session;
}
