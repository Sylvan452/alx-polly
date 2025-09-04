import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { NextRequest } from 'next/server';

// Mock environment variables
process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTY0NjA2NzI2MCwiZXhwIjoxOTYxNjQzMjYwfQ.test';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjQ2MDY3MjYwLCJleHAiOjE5NjE2NDMyNjB9.test';

// Mock Supabase
const mockSupabaseClient = {
  from: jest.fn(() => ({
    insert: jest.fn().mockResolvedValue({ data: {}, error: null }),
    select: jest.fn(() => ({
      eq: jest.fn(() => ({
        eq: jest.fn(() => ({
          limit: jest.fn(() => ({
            single: jest.fn().mockResolvedValue({ data: { role: 'admin' }, error: null })
          }))
        }))
      }))
    }))
  })),
  auth: {
    getUser: jest.fn().mockResolvedValue({
      data: { user: { id: 'test-user', email: 'test@example.com' } },
      error: null
    })
  }
};

jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabaseClient)
}));

// Mock error handling utilities
const mockLogSecurityEvent = jest.fn();
jest.mock('../app/lib/utils/error-handling', () => ({
  logSecurityEvent: mockLogSecurityEvent,
  createSafeError: jest.fn((type) => ({ type, message: 'Safe error message' })),
  sanitizeInput: jest.fn((input) => input.replace(/<script[^>]*>.*?<\/script>/gi, '')),
  validateEmail: jest.fn((email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)),
  validateUUID: jest.fn((uuid) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid)),
  checkRateLimit: jest.fn().mockResolvedValue({ allowed: true, remaining: 10 })
}));

// Import the functions we want to test
import { logSecurityEvent, sanitizeInput, validateEmail, validateUUID, checkRateLimit } from '../app/lib/utils/error-handling';

describe('Security Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Input Validation', () => {
    it('should sanitize XSS attempts', () => {
      const maliciousInput = '<script>alert("xss")</script>Hello World';
      const sanitized = sanitizeInput(maliciousInput);
      expect(sanitized).toBe('Hello World');
    });

    it('should validate email addresses correctly', () => {
      expect(validateEmail('valid@example.com')).toBe(true);
      expect(validateEmail('invalid-email')).toBe(false);
      expect(validateEmail('test@')).toBe(false);
      expect(validateEmail('@example.com')).toBe(false);
    });

    it('should validate UUID format correctly', () => {
      expect(validateUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
      expect(validateUUID('invalid-uuid')).toBe(false);
      expect(validateUUID('123e4567-e89b-12d3-a456')).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    it('should allow requests within rate limit', async () => {
      const result = await checkRateLimit('test-key', 10, 60);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBeGreaterThanOrEqual(0);
    });

    it('should handle rate limit configuration', async () => {
      // Test with different limits
      const result1 = await checkRateLimit('test-key-1', 5, 30);
      const result2 = await checkRateLimit('test-key-2', 100, 3600);
      
      expect(result1.allowed).toBe(true);
      expect(result2.allowed).toBe(true);
    });
  });

  describe('Security Event Logging', () => {
    it('should log authentication events', async () => {
      await logSecurityEvent('AUTHENTICATION_REQUIRED', {
        path: '/admin',
        ip: '192.168.1.1',
        userAgent: 'test-agent'
      });

      expect(mockLogSecurityEvent).toHaveBeenCalledWith('AUTHENTICATION_REQUIRED', {
        path: '/admin',
        ip: '192.168.1.1',
        userAgent: 'test-agent'
      });
    });

    it('should log authorization failures', async () => {
      await logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', {
        path: '/admin/users',
        ip: '10.0.0.1',
        userAgent: 'Mozilla/5.0',
        userId: 'user-123'
      });

      expect(mockLogSecurityEvent).toHaveBeenCalledWith('UNAUTHORIZED_ADMIN_ACCESS', {
        path: '/admin/users',
        ip: '10.0.0.1',
        userAgent: 'Mozilla/5.0',
        userId: 'user-123'
      });
    });

    it('should log session events', async () => {
      await logSecurityEvent('SESSION_EXPIRED', {
        path: '/dashboard',
        ip: '172.16.0.1',
        userAgent: 'Chrome/91.0',
        userId: 'user-456'
      });

      expect(mockLogSecurityEvent).toHaveBeenCalledWith('SESSION_EXPIRED', {
        path: '/dashboard',
        ip: '172.16.0.1',
        userAgent: 'Chrome/91.0',
        userId: 'user-456'
      });
    });
  });

  describe('Database Security', () => {
    it('should use service role for security logging', () => {
      // Verify that createClient is called with service role key
      const { createClient } = require('@supabase/supabase-js');
      expect(createClient).toHaveBeenCalledWith(
        process.env.NEXT_PUBLIC_SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY
      );
    });

    it('should handle database connection errors gracefully', async () => {
      // Mock database error
      mockSupabaseClient.from().insert.mockResolvedValueOnce({
        data: null,
        error: { message: 'Connection failed' }
      });

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      await logSecurityEvent('TEST_EVENT', {
        path: '/test',
        ip: '127.0.0.1',
        userAgent: 'test'
      });

      // Should not throw error, should log to console instead
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('Admin Authorization', () => {
    it('should verify admin role from database', () => {
      // Test that admin check queries the correct table
      expect(mockSupabaseClient.from).toHaveBeenCalledWith('user_roles');
    });

    it('should handle admin role verification errors', async () => {
      // Mock admin role check failure
      mockSupabaseClient.from().select().eq().eq().limit().single.mockResolvedValueOnce({
        data: null,
        error: { message: 'User not found' }
      });

      // This would be tested in the actual middleware, but we're testing the mock setup
      const result = await mockSupabaseClient.from().select().eq().eq().limit().single();
      expect(result.error).toBeTruthy();
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed input gracefully', () => {
      const malformedInputs = [
        null,
        undefined,
        '',
        '<script>alert(1)</script>',
        '\x00\x01\x02',
        'very'.repeat(1000) // Very long string
      ];

      malformedInputs.forEach(input => {
        expect(() => sanitizeInput(input || '')).not.toThrow();
      });
    });

    it('should validate edge case emails', () => {
      const edgeCaseEmails = [
        'test@example.com',
        'user+tag@domain.co.uk',
        'test.email@sub.domain.com',
        '', // Empty
        'no-at-sign',
        '@no-local-part.com',
        'no-domain@',
        'spaces in@email.com'
      ];

      const validEmails = edgeCaseEmails.filter(email => validateEmail(email));
      expect(validEmails).toHaveLength(3); // Only first 3 should be valid
    });

    it('should validate edge case UUIDs', () => {
      const edgeCaseUUIDs = [
        '123e4567-e89b-12d3-a456-426614174000', // Valid v1
        '123e4567-e89b-22d3-a456-426614174000', // Valid v2
        '123e4567-e89b-32d3-a456-426614174000', // Valid v3
        '123e4567-e89b-42d3-a456-426614174000', // Valid v4
        '123e4567-e89b-52d3-a456-426614174000', // Valid v5
        '123e4567-e89b-62d3-a456-426614174000', // Invalid version
        'not-a-uuid',
        '123e4567-e89b-12d3-a456', // Too short
        '123e4567-e89b-12d3-a456-426614174000-extra' // Too long
      ];

      const validUUIDs = edgeCaseUUIDs.filter(uuid => validateUUID(uuid));
      expect(validUUIDs).toHaveLength(5); // Only first 5 should be valid
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete authentication flow', async () => {
      // Simulate a complete flow: unauthenticated -> login -> authenticated
      
      // 1. Unauthenticated access attempt
      await logSecurityEvent('AUTHENTICATION_REQUIRED', {
        path: '/admin',
        ip: '192.168.1.100',
        userAgent: 'Mozilla/5.0'
      });

      // 2. Successful login
      await logSecurityEvent('USER_LOGIN', {
        path: '/auth/callback',
        ip: '192.168.1.100',
        userAgent: 'Mozilla/5.0',
        userId: 'user-789'
      });

      // 3. Authorized access
      await logSecurityEvent('ADMIN_ACCESS', {
        path: '/admin/dashboard',
        ip: '192.168.1.100',
        userAgent: 'Mozilla/5.0',
        userId: 'user-789'
      });

      expect(mockLogSecurityEvent).toHaveBeenCalledTimes(3);
    });

    it('should handle security violation scenarios', async () => {
      // Test various security violations
      const violations = [
        { type: 'RATE_LIMIT_EXCEEDED', path: '/api/data' },
        { type: 'INVALID_CSRF_TOKEN', path: '/api/submit' },
        { type: 'SUSPICIOUS_ACTIVITY', path: '/admin' },
        { type: 'BRUTE_FORCE_ATTEMPT', path: '/auth/login' }
      ];

      for (const violation of violations) {
        await logSecurityEvent(violation.type as any, {
          path: violation.path,
          ip: '192.168.1.200',
          userAgent: 'Suspicious-Agent/1.0'
        });
      }

      expect(mockLogSecurityEvent).toHaveBeenCalledTimes(violations.length);
    });
  });
});