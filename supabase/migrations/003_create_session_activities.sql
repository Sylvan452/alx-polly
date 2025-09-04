-- Migration: Create session activities table for enhanced session management
-- This migration creates the session_activities table to track user session activities
-- and detect suspicious behavior patterns

-- Create session_activities table
CREATE TABLE IF NOT EXISTS session_activities (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_session_activities_user_id ON session_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_session_activities_created_at ON session_activities(created_at);
CREATE INDEX IF NOT EXISTS idx_session_activities_user_created ON session_activities(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_session_activities_ip_address ON session_activities(ip_address);

-- Enable Row Level Security
ALTER TABLE session_activities ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Users can only view their own session activities
CREATE POLICY "Users can view own session activities" ON session_activities
    FOR SELECT
    USING (auth.uid() = user_id);

-- RLS Policy: System can insert session activities (for tracking)
CREATE POLICY "System can insert session activities" ON session_activities
    FOR INSERT
    WITH CHECK (true);

-- RLS Policy: Admins can view all session activities
CREATE POLICY "Admins can view all session activities" ON session_activities
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM user_roles 
            WHERE user_id = auth.uid() 
            AND role = 'admin'
        )
    );

-- RLS Policy: System can delete old session activities (for cleanup)
CREATE POLICY "System can delete old session activities" ON session_activities
    FOR DELETE
    USING (created_at < NOW() - INTERVAL '30 days');

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_session_activities_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER update_session_activities_updated_at_trigger
    BEFORE UPDATE ON session_activities
    FOR EACH ROW
    EXECUTE FUNCTION update_session_activities_updated_at();

-- Function to detect suspicious session activity
CREATE OR REPLACE FUNCTION detect_suspicious_session_activity(target_user_id UUID)
RETURNS TABLE (
    suspicious BOOLEAN,
    unique_ips INTEGER,
    recent_activity_count INTEGER,
    reasons TEXT[]
) AS $$
DECLARE
    ip_count INTEGER;
    activity_count INTEGER;
    reason_list TEXT[] := '{}';
BEGIN
    -- Count unique IPs in the last 24 hours
    SELECT COUNT(DISTINCT ip_address) INTO ip_count
    FROM session_activities
    WHERE user_id = target_user_id
    AND created_at > NOW() - INTERVAL '24 hours';
    
    -- Count activities in the last hour
    SELECT COUNT(*) INTO activity_count
    FROM session_activities
    WHERE user_id = target_user_id
    AND created_at > NOW() - INTERVAL '1 hour';
    
    -- Check for suspicious patterns
    IF ip_count > 3 THEN
        reason_list := array_append(reason_list, 'Multiple IP addresses: ' || ip_count::TEXT);
    END IF;
    
    IF activity_count > 10 THEN
        reason_list := array_append(reason_list, 'High frequency activity: ' || activity_count::TEXT || ' actions in last hour');
    END IF;
    
    RETURN QUERY SELECT 
        array_length(reason_list, 1) > 0,
        ip_count,
        activity_count,
        reason_list;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to cleanup old session activities
CREATE OR REPLACE FUNCTION cleanup_old_session_activities(days_to_keep INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM session_activities
    WHERE created_at < NOW() - (days_to_keep || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get session activity summary for a user
CREATE OR REPLACE FUNCTION get_session_activity_summary(target_user_id UUID)
RETURNS TABLE (
    total_activities INTEGER,
    unique_ips INTEGER,
    last_activity TIMESTAMP WITH TIME ZONE,
    most_common_action TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::INTEGER as total_activities,
        COUNT(DISTINCT ip_address)::INTEGER as unique_ips,
        MAX(created_at) as last_activity,
        (
            SELECT action 
            FROM session_activities sa2 
            WHERE sa2.user_id = target_user_id 
            GROUP BY action 
            ORDER BY COUNT(*) DESC 
            LIMIT 1
        ) as most_common_action
    FROM session_activities
    WHERE user_id = target_user_id
    AND created_at > NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT SELECT, INSERT ON session_activities TO authenticated;
GRANT EXECUTE ON FUNCTION detect_suspicious_session_activity(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION get_session_activity_summary(UUID) TO authenticated;

-- Grant admin permissions for cleanup
GRANT DELETE ON session_activities TO service_role;
GRANT EXECUTE ON FUNCTION cleanup_old_session_activities(INTEGER) TO service_role;

-- Add comment to table
COMMENT ON TABLE session_activities IS 'Tracks user session activities for security monitoring and suspicious behavior detection';
COMMENT ON COLUMN session_activities.action IS 'Type of action performed (login, logout, poll_create, vote, etc.)';
COMMENT ON COLUMN session_activities.ip_address IS 'IP address from which the action was performed';
COMMENT ON COLUMN session_activities.user_agent IS 'Browser user agent string for device identification';