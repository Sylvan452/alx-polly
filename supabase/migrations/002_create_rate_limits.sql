-- Create rate_limits table for persistent rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  identifier VARCHAR(255) NOT NULL, -- IP address, user ID, or other identifier
  action VARCHAR(100) NOT NULL, -- The action being rate limited (auth, poll_creation, etc.)
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE GENERATED ALWAYS AS (created_at + INTERVAL '24 hours') STORED
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier_action ON rate_limits(identifier, action);
CREATE INDEX IF NOT EXISTS idx_rate_limits_created_at ON rate_limits(created_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires_at ON rate_limits(expires_at);

-- Create a composite index for efficient querying
CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup ON rate_limits(identifier, action, created_at);

-- Enable Row Level Security
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

-- Create RLS policies
-- Only allow system/server to manage rate limits (no user access)
CREATE POLICY "System only access" ON rate_limits
  FOR ALL
  USING (false); -- Deny all user access

-- Create a function to clean up expired rate limit entries
CREATE OR REPLACE FUNCTION cleanup_expired_rate_limits()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM rate_limits 
  WHERE expires_at < NOW();
  
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  
  RETURN deleted_count;
END;
$$;

-- Create a function to check rate limit without incrementing
CREATE OR REPLACE FUNCTION check_rate_limit_status(
  p_identifier VARCHAR(255),
  p_action VARCHAR(100),
  p_max_requests INTEGER,
  p_window_minutes INTEGER
)
RETURNS TABLE(
  current_count BIGINT,
  is_allowed BOOLEAN,
  reset_time TIMESTAMP WITH TIME ZONE
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  window_start TIMESTAMP WITH TIME ZONE;
  count_result BIGINT;
  reset_timestamp TIMESTAMP WITH TIME ZONE;
BEGIN
  window_start := NOW() - (p_window_minutes || ' minutes')::INTERVAL;
  reset_timestamp := NOW() + (p_window_minutes || ' minutes')::INTERVAL;
  
  -- Count requests in the current window
  SELECT COUNT(*) INTO count_result
  FROM rate_limits
  WHERE identifier = p_identifier
    AND action = p_action
    AND created_at >= window_start;
  
  RETURN QUERY SELECT 
    count_result,
    (count_result < p_max_requests) as is_allowed,
    reset_timestamp;
END;
$$;

-- Create a function to record a rate limit attempt
CREATE OR REPLACE FUNCTION record_rate_limit_attempt(
  p_identifier VARCHAR(255),
  p_action VARCHAR(100)
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  new_id UUID;
BEGIN
  INSERT INTO rate_limits (identifier, action)
  VALUES (p_identifier, p_action)
  RETURNING id INTO new_id;
  
  RETURN new_id;
END;
$$;

-- Create a scheduled job to clean up old entries (if pg_cron is available)
-- This is optional and depends on the Supabase plan
-- SELECT cron.schedule('cleanup-rate-limits', '0 */6 * * *', 'SELECT cleanup_expired_rate_limits();');

-- Add comments for documentation
COMMENT ON TABLE rate_limits IS 'Stores rate limiting data for persistent rate limiting across server restarts';
COMMENT ON COLUMN rate_limits.identifier IS 'Unique identifier for rate limiting (IP address, user ID, etc.)';
COMMENT ON COLUMN rate_limits.action IS 'The action being rate limited (auth, poll_creation, voting, etc.)';
COMMENT ON COLUMN rate_limits.expires_at IS 'Automatic expiration time (24 hours after creation)';
COMMENT ON FUNCTION cleanup_expired_rate_limits IS 'Removes expired rate limit entries to keep the table clean';
COMMENT ON FUNCTION check_rate_limit_status IS 'Checks current rate limit status without incrementing the counter';
COMMENT ON FUNCTION record_rate_limit_attempt IS 'Records a new rate limit attempt';

-- Grant necessary permissions to the service role
-- Note: In Supabase, the service role typically has full access
-- These grants are mainly for documentation and explicit permission setting
GRANT SELECT, INSERT, DELETE ON rate_limits TO service_role;
GRANT EXECUTE ON FUNCTION cleanup_expired_rate_limits TO service_role;
GRANT EXECUTE ON FUNCTION check_rate_limit_status TO service_role;
GRANT EXECUTE ON FUNCTION record_rate_limit_attempt TO service_role;