"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";
import { checkRateLimit, getClientIP, RATE_LIMITS } from "@/app/lib/utils/rate-limit";
import { headers } from "next/headers";
import { validateCSRF } from "@/app/lib/utils/csrf";
import { validatePollId, validateOptionIndex, sanitizeInput, validateStringLength } from "@/app/lib/utils/validation";
import { trackSessionActivity } from "@/app/lib/utils/session-management";
import { sanitizeError, logSecurityEvent } from "@/app/lib/utils/error-handling";

// Input sanitization function to prevent XSS
// Moved sanitizeInput to validation.ts utility file

// Validate and sanitize poll data
function validatePollData(question: string, options: string[]): { error?: string; sanitizedData?: { question: string; options: string[] } } {
  if (!question || question.trim().length === 0) {
    return { error: "Poll question is required." };
  }
  
  const questionValidation = validateStringLength(question, 1, 500);
  if (!questionValidation.valid) {
    return { error: questionValidation.error };
  }
  
  if (!options || options.length < 2) {
    return { error: "At least 2 options are required." };
  }
  
  if (options.length > 10) {
    return { error: "Maximum 10 options allowed." };
  }
  
  const sanitizedOptions = options.map(option => {
    const sanitized = sanitizeInput(option);
    if (!sanitized || sanitized.length === 0) {
      return null;
    }
    const optionValidation = validateStringLength(sanitized, 1, 200);
    if (!optionValidation.valid) {
      return null;
    }
    return sanitized;
  }).filter(Boolean) as string[];
  
  if (sanitizedOptions.length < 2) {
    return { error: "All options must be valid and non-empty." };
  }
  
  return {
    sanitizedData: {
      question: sanitizeInput(question),
      options: sanitizedOptions
    }
  };
}

// CREATE POLL
export async function createPoll(formData: FormData) {
  // CSRF validation
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  const supabase = await createClient();

  const question = formData.get("question") as string;
  const options = formData.getAll("options").filter(Boolean) as string[];

  // Validate and sanitize input
  const validation = validatePollData(question, options);
  if (validation.error) {
    return { error: validation.error };
  }

  const { question: sanitizedQuestion, options: sanitizedOptions } = validation.sanitizedData!;

  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    return { error: userError.message };
  }
  if (!user) {
    return { error: "You must be logged in to create a poll." };
  }

  const { error } = await supabase.from("polls").insert([
    {
      user_id: user.id,
      question: sanitizedQuestion,
      options: sanitizedOptions,
    },
  ]);

  if (error) {
    const safeError = sanitizeError(error, {
      userId: user.id,
      action: 'poll_create',
      timestamp: new Date().toISOString()
    });
    
    await logSecurityEvent('ERROR_OCCURRED', {
      action: 'poll_create',
      errorCode: safeError.code,
      userId: user.id
    });
    
    return { error: safeError.message };
  }

  // Track poll creation activity
  await trackSessionActivity(user.id, 'poll_create');

  revalidatePath("/polls");
  return { error: null };
}

// GET USER POLLS
export async function getUserPolls() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { polls: [], error: "Not authenticated" };

  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return { polls: [], error: error.message };
  return { polls: data ?? [], error: null };
}

// GET POLL BY ID
export async function getPollById(id: string) {
  // Validate poll ID format
  const idValidation = validatePollId(id);
  if (!idValidation.valid) {
    return { poll: null, error: idValidation.error };
  }

  const supabase = await createClient();
  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("id", id)
    .single();

  if (error) return { poll: null, error: error.message };
  return { poll: data, error: null };
}

// SUBMIT VOTE
export async function submitVote(pollId: string, optionIndex: number) {
  // Validate poll ID format
  const idValidation = validatePollId(pollId);
  if (!idValidation.valid) {
    return { error: idValidation.error };
  }

  const supabase = await createClient();
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();

  // Require authentication to vote
  if (userError || !user) {
    return { error: "You must be logged in to vote." };
  }

  // Rate limiting check
  const headersList = await headers();
  const clientIP = getClientIP(headersList);
  const rateLimitResult = checkRateLimit(`vote:${user.id}:${clientIP}`, RATE_LIMITS.VOTING);
  
  if (!rateLimitResult.success) {
    const resetTime = new Date(rateLimitResult.resetTime);
    return { 
      error: `Too many voting attempts. Please try again after ${resetTime.toLocaleTimeString()}.` 
    };
  }

  // Validate poll exists
  const { data: poll, error: pollError } = await supabase
    .from("polls")
    .select("id, options")
    .eq("id", pollId)
    .single();

  if (pollError || !poll) {
    return { error: "Poll not found." };
  }

  // Validate option index
  const optionValidation = validateOptionIndex(optionIndex, poll.options.length);
  if (!optionValidation.valid) {
    return { error: optionValidation.error };
  }

  // Check if user has already voted on this poll
  const { data: existingVote, error: voteCheckError } = await supabase
    .from("votes")
    .select("id")
    .eq("poll_id", pollId)
    .eq("user_id", user.id)
    .single();

  if (voteCheckError && voteCheckError.code !== 'PGRST116') {
    return { error: "Error checking existing vote." };
  }

  if (existingVote) {
    return { error: "You have already voted on this poll." };
  }

  // Submit the vote
  const { error } = await supabase.from("votes").insert([
    {
      poll_id: pollId,
      user_id: user.id,
      option_index: optionIndex,
      created_at: new Date().toISOString(),
    },
  ]);

  if (error) {
    const safeError = sanitizeError(error, {
      userId: user.id,
      action: 'vote',
      resource: pollId,
      timestamp: new Date().toISOString()
    });
    
    await logSecurityEvent('ERROR_OCCURRED', {
      action: 'vote',
      errorCode: safeError.code,
      pollId,
      userId: user.id
    });
    
    return { error: safeError.message };
  }

  // Track voting activity
  await trackSessionActivity(user.id, 'vote');

  return { error: null };
}

// DELETE POLL (only owner can delete)
export async function deletePoll(formData: FormData) {
  // CSRF validation
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  const id = formData.get("pollId") as string;
  if (!id) {
    return { error: "Poll ID is required." };
  }

  // Validate poll ID format
  const idValidation = validatePollId(id);
  if (!idValidation.valid) {
    return { error: idValidation.error };
  }

  const supabase = await createClient();
  
  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  
  if (userError || !user) {
    return { error: "You must be logged in to delete a poll." };
  }

  // First check if the poll exists and belongs to the user
  const { data: poll, error: fetchError } = await supabase
    .from("polls")
    .select("user_id")
    .eq("id", id)
    .single();

  if (fetchError) {
    return { error: "Poll not found." };
  }

  if (poll.user_id !== user.id) {
    return { error: "You can only delete your own polls." };
  }

  // Delete associated votes first
  await supabase.from("votes").delete().eq("poll_id", id);
  
  // Delete the poll
  const { error } = await supabase.from("polls").delete().eq("id", id).eq("user_id", user.id);
  
  if (error) {
    const safeError = sanitizeError(error, {
      userId: user.id,
      action: 'poll_delete',
      resource: id,
      timestamp: new Date().toISOString()
    });
    
    await logSecurityEvent('ERROR_OCCURRED', {
      action: 'poll_delete',
      errorCode: safeError.code,
      pollId: id,
      userId: user.id
    });
    
    return { error: safeError.message };
  }
  
  // Track poll deletion activity
  await trackSessionActivity(user.id, 'poll_delete');
  
  revalidatePath("/polls");
  return { error: null };
}

// UPDATE POLL
export async function updatePoll(pollId: string, formData: FormData) {
  // CSRF validation
  const csrfValidation = await validateCSRF(formData);
  if (!csrfValidation.valid) {
    return { error: csrfValidation.error || 'Security validation failed' };
  }

  // Validate poll ID format
  const idValidation = validatePollId(pollId);
  if (!idValidation.valid) {
    return { error: idValidation.error };
  }

  const supabase = await createClient();

  const question = formData.get("question") as string;
  const options = formData.getAll("options").filter(Boolean) as string[];

  // Validate and sanitize input
  const validation = validatePollData(question, options);
  if (validation.error) {
    return { error: validation.error };
  }

  const { question: sanitizedQuestion, options: sanitizedOptions } = validation.sanitizedData!;

  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    return { error: userError.message };
  }
  if (!user) {
    return { error: "You must be logged in to update a poll." };
  }

  // Only allow updating polls owned by the user
  const { error } = await supabase
    .from("polls")
    .update({ 
      question: sanitizedQuestion, 
      options: sanitizedOptions,
      updated_at: new Date().toISOString()
    })
    .eq("id", pollId)
    .eq("user_id", user.id);

  if (error) {
    const safeError = sanitizeError(error, {
      userId: user.id,
      action: 'poll_update',
      resource: pollId,
      timestamp: new Date().toISOString()
    });
    
    await logSecurityEvent('ERROR_OCCURRED', {
      action: 'poll_update',
      errorCode: safeError.code,
      pollId,
      userId: user.id
    });
    
    return { error: safeError.message };
  }

  // Track poll update activity
  await trackSessionActivity(user.id, 'poll_update');

  return { error: null };
}
