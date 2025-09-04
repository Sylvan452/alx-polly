// Persistent rate limiting using database storage
import { createClient } from '@/lib/supabase/server';

export interface RateLimit {
  maxRequests: number;
  windowMs: number;
}

export const PERSISTENT_RATE_LIMITS = {
  AUTH: { maxRequests: 5, windowMs: 15 * 60 * 1000 }, // 5 requests per 15 minutes
  POLL_CREATION: { maxRequests: 10, windowMs: 60 * 60 * 1000 }, // 10 polls per hour
  VOTING: { maxRequests: 50, windowMs: 60 * 60 * 1000 }, // 50 votes per hour
  ADMIN_ACTIONS: { maxRequests: 20, windowMs: 60 * 60 * 1000 }, // 20 admin actions per hour
} as const;

export interface RateLimitResult {
  allowed: any;
  success: boolean;
  remaining: number;
  resetTime: Date;
  error?: string;
}

/**
 * Check and update rate limit using database persistence
 * @param identifier - Unique identifier (IP address, user ID, etc.)
 * @param action - The action being rate limited
 * @param limit - Rate limit configuration
 * @returns Promise<RateLimitResult>
 */
export async function checkPersistentRateLimit(
  identifier: string,
  action: string,
  limit: RateLimit,
): Promise<RateLimitResult> {
  const supabase = await createClient();
  const now = new Date();
  const windowStart = new Date(now.getTime() - limit.windowMs);

  try {
    // Clean up old entries first
    await supabase
      .from('rate_limits')
      .delete()
      .lt('created_at', windowStart.toISOString());

    // Count current requests in the window
    const { count, error: countError } = await supabase
      .from('rate_limits')
      .select('*', { count: 'exact', head: true })
      .eq('identifier', identifier)
      .eq('action', action)
      .gte('created_at', windowStart.toISOString());

    if (countError) {
      console.error('Rate limit count error:', countError);
      // Fallback to allowing the request if we can't check
      return {
        success: true,
        remaining: limit.maxRequests - 1,
        resetTime: new Date(now.getTime() + limit.windowMs),
      };
    }

    const currentCount = count || 0;
    const remaining = Math.max(0, limit.maxRequests - currentCount - 1);
    const resetTime = new Date(now.getTime() + limit.windowMs);

    // Check if limit exceeded
    if (currentCount >= limit.maxRequests) {
      return {
        success: false,
        remaining: 0,
        resetTime,
        error: `Rate limit exceeded. Try again after ${new Date(
          resetTime,
        ).toLocaleTimeString()}`,
      };
    }

    // Record this request
    const { error: insertError } = await supabase.from('rate_limits').insert({
      identifier,
      action,
      created_at: now.toISOString(),
    });

    if (insertError) {
      console.error('Rate limit insert error:', insertError);
      // Still allow the request if we can't record it
    }

    return {
      success: true,
      remaining,
      resetTime,
    };
  } catch (error) {
    console.error('Rate limit check error:', error);
    // Fallback to allowing the request
    return {
      success: true,
      remaining: limit.maxRequests - 1,
      resetTime: new Date(now.getTime() + limit.windowMs),
    };
  }
}

/**
 * Get rate limit status without incrementing the counter
 * @param identifier - Unique identifier
 * @param action - The action being checked
 * @param limit - Rate limit configuration
 * @returns Promise<RateLimitResult>
 */
export async function getRateLimitStatus(
  identifier: string,
  action: string,
  limit: RateLimit,
): Promise<RateLimitResult> {
  const supabase = await createClient();
  const now = new Date();
  const windowStart = new Date(now.getTime() - limit.windowMs);

  try {
    const { count, error } = await supabase
      .from('rate_limits')
      .select('*', { count: 'exact', head: true })
      .eq('identifier', identifier)
      .eq('action', action)
      .gte('created_at', windowStart.toISOString());

    if (error) {
      console.error('Rate limit status error:', error);
      return {
        success: true,
        remaining: limit.maxRequests,
        resetTime: new Date(now.getTime() + limit.windowMs),
      };
    }

    const currentCount = count || 0;
    const remaining = Math.max(0, limit.maxRequests - currentCount);
    const resetTime = new Date(now.getTime() + limit.windowMs);

    return {
      success: currentCount < limit.maxRequests,
      remaining,
      resetTime,
    };
  } catch (error) {
    console.error('Rate limit status check error:', error);
    return {
      success: true,
      remaining: limit.maxRequests,
      resetTime: new Date(now.getTime() + limit.windowMs),
    };
  }
}

/**
 * Clear rate limit entries for a specific identifier and action
 * @param identifier - Unique identifier
 * @param action - The action to clear (optional, clears all if not specified)
 * @returns Promise<boolean>
 */
export async function clearRateLimit(
  identifier: string,
  action?: string,
): Promise<boolean> {
  const supabase = await createClient();

  try {
    let query = supabase
      .from('rate_limits')
      .delete()
      .eq('identifier', identifier);

    if (action) {
      query = query.eq('action', action);
    }

    const { error } = await query;

    if (error) {
      console.error('Rate limit clear error:', error);
      return false;
    }

    return true;
  } catch (error) {
    console.error('Rate limit clear error:', error);
    return false;
  }
}

/**
 * Clean up old rate limit entries (should be run periodically)
 * @param olderThanMs - Remove entries older than this many milliseconds
 * @returns Promise<number> - Number of entries removed
 */
export async function cleanupOldRateLimits(
  olderThanMs: number = 24 * 60 * 60 * 1000,
): Promise<number> {
  const supabase = await createClient();
  const cutoffTime = new Date(Date.now() - olderThanMs);

  try {
    const { count, error } = await supabase
      .from('rate_limits')
      .delete()
      .lt('created_at', cutoffTime.toISOString());

    if (error) {
      console.error('Rate limit cleanup error:', error);
      return 0;
    }

    return count || 0;
  } catch (error) {
    console.error('Rate limit cleanup error:', error);
    return 0;
  }
}

/**
 * Get client IP address for rate limiting
 * @param headers - Request headers
 * @returns string - Client IP address
 */
export function getClientIP(headers: Headers): string {
  // Check various headers for the real IP
  const xForwardedFor = headers.get('x-forwarded-for');
  const xRealIP = headers.get('x-real-ip');
  const cfConnectingIP = headers.get('cf-connecting-ip');

  if (xForwardedFor) {
    // x-forwarded-for can contain multiple IPs, take the first one
    return xForwardedFor.split(',')[0].trim();
  }

  if (xRealIP) {
    return xRealIP;
  }

  if (cfConnectingIP) {
    return cfConnectingIP;
  }

  // Fallback to a default value
  return 'unknown';
}
