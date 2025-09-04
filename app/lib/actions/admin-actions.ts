'use server';

import { createClient } from '@/lib/supabase/server';
import { revalidatePath } from 'next/cache';
import { validateCSRF } from '@/app/lib/utils/csrf';
import { validatePollId } from '@/app/lib/utils/validation';
import { isUserAdmin as checkAdminStatus } from '@/app/lib/utils/admin';
import { trackSessionActivity } from '@/app/lib/utils/session-management';
import {
  sanitizeError,
  logSecurityEvent,
} from '@/app/lib/utils/error-handling';

// Check if user is admin
export async function isUserAdmin() {
  return await checkAdminStatus();
}

// Get all polls (admin only)
export async function getAllPolls() {
  const supabase = await createClient();

  // Check admin authorization
  const isAdmin = await isUserAdmin();
  if (!isAdmin) {
    return { polls: [], error: 'Unauthorized: Admin access required' };
  }

  const { data, error } = await supabase
    .from('polls')
    .select('*')
    .order('created_at', { ascending: false });

  if (error) {
    return { polls: [], error: error.message };
  }

  return { polls: data || [], error: null };
}

// Delete any poll (admin only)
export async function adminDeletePoll(formData: FormData) {
  // CSRF validation
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  const pollId = formData.get('pollId') as string;
  if (!pollId) {
    return { error: 'Poll ID is required.' };
  }

  // Validate poll ID format
  const idValidation = validatePollId(pollId);
  if (!idValidation.valid) {
    return { error: idValidation.error };
  }

  const supabase = await createClient();

  // ✅ Fetch user early so it’s available for logging and tracking
  const {
    data: { user },
  } = await supabase.auth.getUser();

  // Check admin authorization
  const isAdmin = await isUserAdmin();
  if (!isAdmin) {
    return { error: 'Unauthorized: Admin access required' };
  }

  // Delete associated votes first
  await supabase.from('votes').delete().eq('poll_id', pollId);

  // Delete the poll
  const { error: deleteError } = await supabase
    .from('polls')
    .delete()
    .eq('id', pollId);

  if (deleteError) {
    const safeError = sanitizeError(deleteError, {
      userId: user?.id,
      action: 'admin_poll_delete',
      resource: pollId,
      timestamp: new Date().toISOString(),
    });

    if (user) {
      logSecurityEvent('ERROR_OCCURRED', {
        action: 'admin_poll_delete',
        errorCode: safeError.code,
        pollId,
      });
    }

    return { error: safeError.message };
  }

  // Track admin poll deletion activity
  if (user) {
    await trackSessionActivity(user.id, 'admin_poll_delete');
  }

  revalidatePath('/admin');
  return { error: null };
}

// Get user statistics (admin only)
export async function getUserStats() {
  const supabase = await createClient();

  // Check admin authorization
  const isAdmin = await isUserAdmin();
  if (!isAdmin) {
    return { stats: null, error: 'Unauthorized: Admin access required' };
  }

  // Get total users count
  const { count: userCount } = await supabase
    .from('auth.users')
    .select('*', { count: 'exact', head: true });

  // Get total polls count
  const { count: pollCount } = await supabase
    .from('polls')
    .select('*', { count: 'exact', head: true });

  // Get total votes count
  const { count: voteCount } = await supabase
    .from('votes')
    .select('*', { count: 'exact', head: true });

  return {
    stats: {
      totalUsers: userCount || 0,
      totalPolls: pollCount || 0,
      totalVotes: voteCount || 0,
    },
    error: null,
  };
}
