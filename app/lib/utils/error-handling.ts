// Error handling utilities to prevent information disclosure
import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

export interface SafeError {
  message: string;
  code?: string;
  statusCode: number;
}

export interface ErrorContext {
  userId?: string;
  action?: string;
  resource?: string;
  timestamp: string;
}

// Safe error messages that don't expose internal details
export const SAFE_ERROR_MESSAGES = {
  // Authentication errors
  INVALID_CREDENTIALS: 'Invalid email or password',
  SESSION_EXPIRED: 'Your session has expired. Please log in again',
  UNAUTHORIZED: 'You are not authorized to perform this action',
  FORBIDDEN: 'Access denied',
  
  // Validation errors
  INVALID_INPUT: 'Invalid input provided',
  MISSING_REQUIRED_FIELD: 'Required field is missing',
  INVALID_FORMAT: 'Invalid format provided',
  
  // Resource errors
  RESOURCE_NOT_FOUND: 'The requested resource was not found',
  RESOURCE_CONFLICT: 'A conflict occurred with the current resource state',
  
  // Rate limiting
  RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later',
  
  // Generic errors
  INTERNAL_ERROR: 'An internal error occurred. Please try again later',
  SERVICE_UNAVAILABLE: 'Service is temporarily unavailable',
  NETWORK_ERROR: 'Network error occurred. Please check your connection',
  
  // Database errors
  DATABASE_ERROR: 'A database error occurred. Please try again',
  TRANSACTION_FAILED: 'Transaction failed. Please try again',
  
  // File/Upload errors
  FILE_TOO_LARGE: 'File size exceeds the maximum limit',
  INVALID_FILE_TYPE: 'Invalid file type',
  UPLOAD_FAILED: 'File upload failed. Please try again'
} as const;

/**
 * Security event logging utility
 * SECURITY: Centralized logging for security-related events
 */

type SecurityEventType = 
  | 'AUTH_ERROR'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'UNAUTHORIZED_API_ACCESS'
  | 'UNAUTHORIZED_ADMIN_ACCESS'
  | 'SESSION_EXPIRED'
  | 'ADMIN_ACCESS'
  | 'ADMIN_CHECK_ERROR'
  | 'RATE_LIMIT_EXCEEDED'
  | 'CSRF_TOKEN_MISMATCH'
  | 'INVALID_INPUT'
  | 'SUSPICIOUS_ACTIVITY';

interface SecurityEventData {
  userId?: string;
  path?: string;
  ip?: string;
  userAgent?: string;
  error?: string;
  sessionAge?: number;
  [key: string]: any;
}

/**
 * Log security events to Supabase for monitoring and analysis
 * Uses service role key for secure logging
 */
export async function logSecurityEvent(
  eventType: SecurityEventType,
  data: SecurityEventData
): Promise<void> {
  try {
    // Use service role for logging (server-side only)
    const supabase = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    );

    const { error } = await supabase
      .from('session_activities')
      .insert({
        user_id: data.userId || null,
        activity_type: eventType,
        ip_address: data.ip || 'unknown',
        user_agent: data.userAgent || 'unknown',
        metadata: {
          path: data.path,
          error: data.error,
          sessionAge: data.sessionAge,
          ...data
        },
        created_at: new Date().toISOString()
      });

    if (error) {
      console.error('Failed to log security event:', error);
      // Fallback to console logging if database logging fails
      console.warn('Security Event:', {
        type: eventType,
        timestamp: new Date().toISOString(),
        ...data
      });
    }
  } catch (error) {
    // Fallback logging to console if Supabase is unavailable
    console.error('Security logging error:', error);
    console.warn('Security Event (fallback):', {
      type: eventType,
      timestamp: new Date().toISOString(),
      ...data
    });
  }
}

// Error codes that should be logged but not exposed
const SENSITIVE_ERROR_PATTERNS = [
  /password/i,
  /secret/i,
  /key/i,
  /token/i,
  /connection string/i,
  /database/i,
  /sql/i,
  /query/i,
  /internal/i,
  /stack trace/i,
  /file path/i,
  /directory/i,
  /environment/i,
  /config/i
];

/**
 * Sanitize error message to prevent information disclosure
 * @param error - Original error object or message
 * @param context - Error context for logging
 * @returns Sanitized error message
 */
export function sanitizeError(error: any, context?: ErrorContext): SafeError {
  const timestamp = new Date().toISOString();
  const errorContext = { ...context, timestamp };
  
  // Log the original error for debugging (server-side only)
  if (typeof window === 'undefined') {
    console.error('Original error:', {
      error: error instanceof Error ? {
        message: error.message,
        stack: error.stack,
        name: error.name
      } : error,
      context: errorContext
    });
  }
  
  let originalMessage = '';
  let statusCode = 500;
  
  if (error instanceof Error) {
    originalMessage = error.message;
  } else if (typeof error === 'string') {
    originalMessage = error;
  } else if (error?.message) {
    originalMessage = error.message;
  }
  
  // Determine status code based on error type
  statusCode = determineStatusCode(error, originalMessage);
  
  // Check if error message contains sensitive information
  const containsSensitiveInfo = SENSITIVE_ERROR_PATTERNS.some(pattern => 
    pattern.test(originalMessage)
  );
  
  if (containsSensitiveInfo) {
    return {
      message: SAFE_ERROR_MESSAGES.INTERNAL_ERROR,
      code: 'INTERNAL_ERROR',
      statusCode
    };
  }
  
  // Map common error patterns to safe messages
  const safeMessage = mapToSafeMessage(originalMessage, statusCode);
  
  return {
    message: safeMessage,
    code: getSafeErrorCode(originalMessage),
    statusCode
  };
}

/**
 * Determine HTTP status code based on error
 * @param error - Error object
 * @param message - Error message
 * @returns HTTP status code
 */
function determineStatusCode(error: any, message: string): number {
  // Check for specific error types
  if (error?.code === 'PGRST116' || message.includes('not found')) {
    return 404;
  }
  
  if (error?.code === 'PGRST301' || message.includes('unauthorized') || message.includes('invalid credentials')) {
    return 401;
  }
  
  if (error?.code === 'PGRST302' || message.includes('forbidden') || message.includes('access denied')) {
    return 403;
  }
  
  if (message.includes('rate limit') || message.includes('too many requests')) {
    return 429;
  }
  
  if (message.includes('validation') || message.includes('invalid input') || message.includes('bad request')) {
    return 400;
  }
  
  if (message.includes('conflict') || message.includes('already exists')) {
    return 409;
  }
  
  if (message.includes('service unavailable') || message.includes('timeout')) {
    return 503;
  }
  
  return 500;
}

/**
 * Map error message to safe user-friendly message
 * @param originalMessage - Original error message
 * @param statusCode - HTTP status code
 * @returns Safe error message
 */
function mapToSafeMessage(originalMessage: string, statusCode: number): string {
  const lowerMessage = originalMessage.toLowerCase();
  
  // Authentication/Authorization errors
  if (lowerMessage.includes('invalid credentials') || lowerMessage.includes('wrong password')) {
    return SAFE_ERROR_MESSAGES.INVALID_CREDENTIALS;
  }
  
  if (lowerMessage.includes('session') && lowerMessage.includes('expired')) {
    return SAFE_ERROR_MESSAGES.SESSION_EXPIRED;
  }
  
  if (lowerMessage.includes('unauthorized') || statusCode === 401) {
    return SAFE_ERROR_MESSAGES.UNAUTHORIZED;
  }
  
  if (lowerMessage.includes('forbidden') || statusCode === 403) {
    return SAFE_ERROR_MESSAGES.FORBIDDEN;
  }
  
  // Resource errors
  if (lowerMessage.includes('not found') || statusCode === 404) {
    return SAFE_ERROR_MESSAGES.RESOURCE_NOT_FOUND;
  }
  
  if (lowerMessage.includes('conflict') || lowerMessage.includes('already exists') || statusCode === 409) {
    return SAFE_ERROR_MESSAGES.RESOURCE_CONFLICT;
  }
  
  // Rate limiting
  if (lowerMessage.includes('rate limit') || lowerMessage.includes('too many') || statusCode === 429) {
    return SAFE_ERROR_MESSAGES.RATE_LIMIT_EXCEEDED;
  }
  
  // Validation errors
  if (lowerMessage.includes('validation') || lowerMessage.includes('invalid') || statusCode === 400) {
    return SAFE_ERROR_MESSAGES.INVALID_INPUT;
  }
  
  // Service errors
  if (lowerMessage.includes('service unavailable') || lowerMessage.includes('timeout') || statusCode === 503) {
    return SAFE_ERROR_MESSAGES.SERVICE_UNAVAILABLE;
  }
  
  // Network errors
  if (lowerMessage.includes('network') || lowerMessage.includes('connection')) {
    return SAFE_ERROR_MESSAGES.NETWORK_ERROR;
  }
  
  // Database errors
  if (lowerMessage.includes('database') || lowerMessage.includes('sql') || lowerMessage.includes('query')) {
    return SAFE_ERROR_MESSAGES.DATABASE_ERROR;
  }
  
  // File upload errors
  if (lowerMessage.includes('file') && lowerMessage.includes('large')) {
    return SAFE_ERROR_MESSAGES.FILE_TOO_LARGE;
  }
  
  if (lowerMessage.includes('file') && lowerMessage.includes('type')) {
    return SAFE_ERROR_MESSAGES.INVALID_FILE_TYPE;
  }
  
  if (lowerMessage.includes('upload')) {
    return SAFE_ERROR_MESSAGES.UPLOAD_FAILED;
  }
  
  // Default to generic error
  return SAFE_ERROR_MESSAGES.INTERNAL_ERROR;
}

/**
 * Get safe error code for client consumption
 * @param originalMessage - Original error message
 * @returns Safe error code
 */
function getSafeErrorCode(originalMessage: string): string {
  const lowerMessage = originalMessage.toLowerCase();
  
  if (lowerMessage.includes('not found')) return 'NOT_FOUND';
  if (lowerMessage.includes('unauthorized')) return 'UNAUTHORIZED';
  if (lowerMessage.includes('forbidden')) return 'FORBIDDEN';
  if (lowerMessage.includes('validation') || lowerMessage.includes('invalid')) return 'VALIDATION_ERROR';
  if (lowerMessage.includes('rate limit')) return 'RATE_LIMITED';
  if (lowerMessage.includes('conflict')) return 'CONFLICT';
  
  return 'INTERNAL_ERROR';
}

/**
 * Create a safe error response for API routes
 * @param error - Original error
 * @param context - Error context
 * @returns NextResponse with sanitized error
 */
export function createErrorResponse(error: any, context?: ErrorContext): NextResponse {
  const safeError = sanitizeError(error, context);
  
  return NextResponse.json(
    {
      error: {
        message: safeError.message,
        code: safeError.code
      }
    },
    { status: safeError.statusCode }
  );
}

/**
 * Wrapper for server actions to handle errors safely
 * @param action - Server action function
 * @param context - Error context
 * @returns Wrapped action with error handling
 */
export function withErrorHandling<T extends any[], R>(
  action: (...args: T) => Promise<R>,
  context?: Omit<ErrorContext, 'timestamp'>
) {
  return async (...args: T): Promise<R | { error: string }> => {
    try {
      return await action(...args);
    } catch (error) {
      const safeError = sanitizeError(error, context);
      return { error: safeError.message };
    }
  };
}

/**
 * Log security events for monitoring
 * @param event - Security event type
 * @param details - Event details
 * @param userId - User ID if available
 */
export function logSecurityEvent(
  event: 'UNAUTHORIZED_ACCESS' | 'RATE_LIMIT_EXCEEDED' | 'SUSPICIOUS_ACTIVITY' | 'ERROR_OCCURRED',
  details: Record<string, any>,
  userId?: string
) {
  if (typeof window !== 'undefined') {
    return; // Don't log on client side
  }
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    userId,
    details: {
      ...details,
      // Remove sensitive information from logs
      userAgent: details.userAgent ? '[REDACTED]' : undefined,
      ipAddress: details.ipAddress ? '[REDACTED]' : undefined
    }
  };
  
  console.warn('Security Event:', logEntry);
  
  // In production, you might want to send this to a security monitoring service
  // await sendToSecurityMonitoring(logEntry);
}

/**
 * Validate and sanitize user input to prevent injection attacks
 * @param input - User input
 * @param maxLength - Maximum allowed length
 * @returns Sanitized input or throws error
 */
export function validateAndSanitizeInput(input: string, maxLength: number = 1000): string {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }
  
  if (input.length > maxLength) {
    throw new Error(`Input exceeds maximum length of ${maxLength} characters`);
  }
  
  // Remove potentially dangerous characters
  const sanitized = input
    .replace(/<script[^>]*>.*?<\/script>/gi, '') // Remove script tags
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .trim();
  
  return sanitized;
}

/**
 * Check if error should be reported to external monitoring
 * @param error - Error object
 * @returns Whether error should be reported
 */
export function shouldReportError(error: any): boolean {
  const message = error?.message || error || '';
  const lowerMessage = message.toLowerCase();
  
  // Don't report validation errors or user errors
  if (lowerMessage.includes('validation') || 
      lowerMessage.includes('invalid input') ||
      lowerMessage.includes('not found') ||
      lowerMessage.includes('unauthorized')) {
    return false;
  }
  
  // Report system errors
  return true;
}