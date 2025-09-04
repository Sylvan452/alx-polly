// Input validation utilities

/**
 * Validates if a string is a valid UUID v4
 * @param uuid - The string to validate
 * @returns boolean indicating if the string is a valid UUID
 */
export function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Validates and sanitizes a poll ID
 * @param pollId - The poll ID to validate
 * @returns object with validation result and error message if invalid
 */
export function validatePollId(pollId: string): { valid: boolean; error?: string } {
  if (!pollId || typeof pollId !== 'string') {
    return { valid: false, error: 'Poll ID is required and must be a string' };
  }

  if (!isValidUUID(pollId)) {
    return { valid: false, error: 'Invalid poll ID format' };
  }

  return { valid: true };
}

/**
 * Validates option index for voting
 * @param optionIndex - The option index to validate
 * @param maxOptions - Maximum number of options allowed
 * @returns object with validation result and error message if invalid
 */
export function validateOptionIndex(optionIndex: number, maxOptions: number): { valid: boolean; error?: string } {
  if (typeof optionIndex !== 'number' || isNaN(optionIndex)) {
    return { valid: false, error: 'Option index must be a valid number' };
  }

  if (optionIndex < 0 || optionIndex >= maxOptions) {
    return { valid: false, error: 'Invalid option selected' };
  }

  return { valid: true };
}

/**
 * Sanitizes text input to prevent XSS
 * @param input - The input string to sanitize
 * @returns sanitized string
 */
export function sanitizeInput(input: string): string {
  if (typeof input !== 'string') {
    return '';
  }
  
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}

/**
 * Validates email format
 * @param email - The email to validate
 * @returns boolean indicating if email is valid
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validates string length within bounds
 * @param str - The string to validate
 * @param minLength - Minimum length allowed
 * @param maxLength - Maximum length allowed
 * @returns object with validation result and error message if invalid
 */
export function validateStringLength(str: string, minLength: number, maxLength: number): { valid: boolean; error?: string } {
  if (typeof str !== 'string') {
    return { valid: false, error: 'Input must be a string' };
  }

  const trimmed = str.trim();
  
  if (trimmed.length < minLength) {
    return { valid: false, error: `Input must be at least ${minLength} characters long` };
  }

  if (trimmed.length > maxLength) {
    return { valid: false, error: `Input must be no more than ${maxLength} characters long` };
  }

  return { valid: true };
}