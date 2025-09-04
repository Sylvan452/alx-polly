import { createClient } from '@/lib/supabase/server';
import { logSecurityEvent } from './error-handling';

/**
 * Securely checks if a user has admin privileges
 * SECURITY: Only checks database roles, no environment variable fallback
 * @param userId - Optional user ID, defaults to current authenticated user
 * @returns Promise<boolean> - true if user is admin, false otherwise
 */
export async function isUserAdmin(userId?: string): Promise<boolean> {
  try {
    const supabase = await createClient();
    
    // Get current user if no userId provided
    let targetUserId = userId;
    if (!targetUserId) {
      const { data: { user }, error: userError } = await supabase.auth.getUser();
      if (userError || !user) {
        return false;
      }
      targetUserId = user.id;
    }

    // SECURITY: Only check database roles - no environment variable fallback
    const { data: roles, error } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', targetUserId)
      .eq('role', 'admin')
      .limit(1);

    if (error) {
      // Log security event for admin check failures
      await logSecurityEvent('ADMIN_CHECK_FAILED', {
        error: error.message,
        userId: targetUserId
      }, targetUserId);
      return false;
    }

    const isAdmin = roles && roles.length > 0;
    
    // Log admin access attempts for security monitoring
    if (isAdmin) {
      await logSecurityEvent('ADMIN_ACCESS_GRANTED', {
        userId: targetUserId
      }, targetUserId);
    }

    return isAdmin;
  } catch (error) {
    // Log any unexpected errors
    await logSecurityEvent('ADMIN_CHECK_ERROR', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: userId || 'unknown'
    });
    return false;
  }
}

/**
 * Grants admin role to a user (admin only)
 * @param targetUserId - User ID to grant admin role to
 * @param grantedBy - Admin user ID granting the role
 * @returns Promise<{success: boolean, error?: string}>
 */
export async function grantAdminRole(targetUserId: string, grantedBy?: string): Promise<{success: boolean, error?: string}> {
  try {
    const supabase = await createClient();
    
    // Verify the granting user is admin
    const isGranterAdmin = await isUserAdmin(grantedBy);
    if (!isGranterAdmin) {
      await logSecurityEvent('UNAUTHORIZED_ADMIN_GRANT_ATTEMPT', {
        targetUserId,
        attemptedBy: grantedBy || 'unknown'
      });
      return { success: false, error: 'Unauthorized: Admin access required' };
    }

    // Check if user already has admin role
    const { data: existingRole } = await supabase
      .from('user_roles')
      .select('id')
      .eq('user_id', targetUserId)
      .eq('role', 'admin')
      .limit(1);

    if (existingRole && existingRole.length > 0) {
      return { success: false, error: 'User already has admin role' };
    }

    // Grant admin role
    const { error } = await supabase
      .from('user_roles')
      .insert({
        user_id: targetUserId,
        role: 'admin',
        granted_by: grantedBy
      });

    if (error) {
      await logSecurityEvent('ADMIN_GRANT_FAILED', {
        targetUserId,
        grantedBy: grantedBy || 'unknown',
        error: error.message
      });
      return { success: false, error: error.message };
    }

    await logSecurityEvent('ADMIN_ROLE_GRANTED', {
      targetUserId,
      grantedBy: grantedBy || 'unknown'
    });

    return { success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await logSecurityEvent('ADMIN_GRANT_ERROR', {
      targetUserId,
      grantedBy: grantedBy || 'unknown',
      error: errorMessage
    });
    return { success: false, error: errorMessage };
  }
}

/**
 * Revokes admin role from a user (admin only)
 * @param targetUserId - User ID to revoke admin role from
 * @param revokedBy - Admin user ID revoking the role
 * @returns Promise<{success: boolean, error?: string}>
 */
export async function revokeAdminRole(targetUserId: string, revokedBy?: string): Promise<{success: boolean, error?: string}> {
  try {
    const supabase = await createClient();
    
    // Verify the revoking user is admin
    const isRevokerAdmin = await isUserAdmin(revokedBy);
    if (!isRevokerAdmin) {
      await logSecurityEvent('UNAUTHORIZED_ADMIN_REVOKE_ATTEMPT', {
        targetUserId,
        attemptedBy: revokedBy || 'unknown'
      });
      return { success: false, error: 'Unauthorized: Admin access required' };
    }

    // Prevent self-revocation
    if (targetUserId === revokedBy) {
      await logSecurityEvent('ADMIN_SELF_REVOKE_ATTEMPT', {
        userId: targetUserId
      });
      return { success: false, error: 'Cannot revoke your own admin role' };
    }

    // Revoke admin role
    const { error } = await supabase
      .from('user_roles')
      .delete()
      .eq('user_id', targetUserId)
      .eq('role', 'admin');

    if (error) {
      await logSecurityEvent('ADMIN_REVOKE_FAILED', {
        targetUserId,
        revokedBy: revokedBy || 'unknown',
        error: error.message
      });
      return { success: false, error: error.message };
    }

    await logSecurityEvent('ADMIN_ROLE_REVOKED', {
      targetUserId,
      revokedBy: revokedBy || 'unknown'
    });

    return { success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await logSecurityEvent('ADMIN_REVOKE_ERROR', {
      targetUserId,
      revokedBy: revokedBy || 'unknown',
      error: errorMessage
    });
    return { success: false, error: errorMessage };
  }
}

/**
 * Lists all admin users (admin only)
 * @param requestedBy - Admin user ID requesting the list
 * @returns Promise<{admins: Array, error?: string}>
 */
export async function listAdminUsers(requestedBy?: string): Promise<{admins: any[], error?: string}> {
  try {
    const supabase = await createClient();
    
    // Verify the requesting user is admin
    const isRequesterAdmin = await isUserAdmin(requestedBy);
    if (!isRequesterAdmin) {
      await logSecurityEvent('UNAUTHORIZED_ADMIN_LIST_ATTEMPT', {
        attemptedBy: requestedBy || 'unknown'
      });
      return { admins: [], error: 'Unauthorized: Admin access required' };
    }

    // Get all admin users with profile information
    const { data: admins, error } = await supabase
      .from('user_roles')
      .select(`
        user_id,
        granted_by,
        granted_at,
        profiles!user_roles_user_id_fkey (
          email,
          full_name
        )
      `)
      .eq('role', 'admin')
      .order('granted_at', { ascending: false });

    if (error) {
      await logSecurityEvent('ADMIN_LIST_FAILED', {
        requestedBy: requestedBy || 'unknown',
        error: error.message
      });
      return { admins: [], error: error.message };
    }

    await logSecurityEvent('ADMIN_LIST_ACCESSED', {
      requestedBy: requestedBy || 'unknown',
      adminCount: admins?.length || 0
    });

    return { admins: admins || [], error: undefined };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await logSecurityEvent('ADMIN_LIST_ERROR', {
      requestedBy: requestedBy || 'unknown',
      error: errorMessage
    });
    return { admins: [], error: errorMessage };
  }
}

/**
 * DEPRECATED: Legacy function for backward compatibility
 * Use isUserAdmin() instead
 */
export async function checkAdminStatus(): Promise<boolean> {
  console.warn('checkAdminStatus() is deprecated. Use isUserAdmin() instead.');
  return await isUserAdmin();
}
