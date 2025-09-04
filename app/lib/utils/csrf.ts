import { cookies } from 'next/headers';
import { randomBytes, createHash } from 'crypto';

// Generate a CSRF token
export function generateCSRFToken(): string {
  return randomBytes(32).toString('hex');
}

// Set CSRF token in cookies
export async function setCSRFToken(): Promise<string> {
  const token = generateCSRFToken();
  const cookieStore = await cookies();
  
  cookieStore.set('csrf-token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24, // 24 hours
    path: '/'
  });
  
  return token;
}

// Get CSRF token from cookies
export async function getCSRFToken(): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get('csrf-token')?.value;
}

// Verify CSRF token
export async function verifyCSRFToken(submittedToken: string): Promise<boolean> {
  const storedToken = await getCSRFToken();
  
  if (!storedToken || !submittedToken) {
    return false;
  }
  
  // Use timing-safe comparison
  const storedHash = createHash('sha256').update(storedToken).digest('hex');
  const submittedHash = createHash('sha256').update(submittedToken).digest('hex');
  
  return storedHash === submittedHash;
}

// CSRF validation for server actions
export async function validateCSRF(formData: FormData): Promise<{ valid: boolean; error?: string }> {
  const submittedToken = formData.get('csrf-token') as string;
  
  if (!submittedToken) {
    return { valid: false, error: 'CSRF token missing' };
  }
  
  const isValid = await verifyCSRFToken(submittedToken);
  
  if (!isValid) {
    return { valid: false, error: 'Invalid CSRF token' };
  }
  
  return { valid: true };
}