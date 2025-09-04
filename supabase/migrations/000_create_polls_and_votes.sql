-- Migration: Create polls and votes tables with proper RLS policies
-- This migration creates the core polling functionality tables that were missing

-- Create polls table
CREATE TABLE IF NOT EXISTS polls (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    question TEXT NOT NULL CHECK (length(question) >= 5 AND length(question) <= 500),
    options JSONB NOT NULL CHECK (jsonb_array_length(options) >= 2 AND jsonb_array_length(options) <= 10),
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Create votes table
CREATE TABLE IF NOT EXISTS votes (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    poll_id UUID NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    option_index INTEGER NOT NULL CHECK (option_index >= 0),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_polls_user_id ON polls(user_id);
CREATE INDEX IF NOT EXISTS idx_polls_created_at ON polls(created_at);
CREATE INDEX IF NOT EXISTS idx_polls_is_active ON polls(is_active);
CREATE INDEX IF NOT EXISTS idx_polls_expires_at ON polls(expires_at);

CREATE INDEX IF NOT EXISTS idx_votes_poll_id ON votes(poll_id);
CREATE INDEX IF NOT EXISTS idx_votes_user_id ON votes(user_id);
CREATE INDEX IF NOT EXISTS idx_votes_created_at ON votes(created_at);
CREATE INDEX IF NOT EXISTS idx_votes_ip_address ON votes(ip_address);

-- Unique constraint to prevent duplicate votes from same user
CREATE UNIQUE INDEX IF NOT EXISTS idx_votes_unique_user_poll ON votes(poll_id, user_id) WHERE user_id IS NOT NULL;

-- Enable Row Level Security
ALTER TABLE polls ENABLE ROW LEVEL SECURITY;
ALTER TABLE votes ENABLE ROW LEVEL SECURITY;

-- RLS Policies for polls table
CREATE POLICY "Users can view active polls" ON polls
    FOR SELECT
    USING (is_active = true AND (expires_at IS NULL OR expires_at > NOW()));

CREATE POLICY "Users can view their own polls" ON polls
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own polls" ON polls
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own polls" ON polls
    FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own polls" ON polls
    FOR DELETE
    USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all polls" ON polls
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM user_roles 
            WHERE user_id = auth.uid() 
            AND role = 'admin'
        )
    );

CREATE POLICY "Admins can delete any poll" ON polls
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM user_roles 
            WHERE user_id = auth.uid() 
            AND role = 'admin'
        )
    );

-- RLS Policies for votes table
CREATE POLICY "Users can view votes for active polls" ON votes
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM polls 
            WHERE polls.id = votes.poll_id 
            AND polls.is_active = true 
            AND (polls.expires_at IS NULL OR polls.expires_at > NOW())
        )
    );

CREATE POLICY "Users can insert votes for active polls" ON votes
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM polls 
            WHERE polls.id = votes.poll_id 
            AND polls.is_active = true 
            AND (polls.expires_at IS NULL OR polls.expires_at > NOW())
        )
        AND (auth.uid() = user_id OR user_id IS NULL)
    );

CREATE POLICY "Users can view their own votes" ON votes
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Poll owners can view votes on their polls" ON votes
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM polls 
            WHERE polls.id = votes.poll_id 
            AND polls.user_id = auth.uid()
        )
    );

CREATE POLICY "Admins can view all votes" ON votes
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM user_roles 
            WHERE user_id = auth.uid() 
            AND role = 'admin'
        )
    );

CREATE POLICY "Admins can delete any vote" ON votes
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM user_roles 
            WHERE user_id = auth.uid() 
            AND role = 'admin'
        )
    );

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_polls_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER update_polls_updated_at_trigger
    BEFORE UPDATE ON polls
    FOR EACH ROW
    EXECUTE FUNCTION update_polls_updated_at();

-- Function to validate poll options
CREATE OR REPLACE FUNCTION validate_poll_options(options JSONB)
RETURNS BOOLEAN AS $$
BEGIN
    -- Check if options is an array
    IF jsonb_typeof(options) != 'array' THEN
        RETURN FALSE;
    END IF;
    
    -- Check array length
    IF jsonb_array_length(options) < 2 OR jsonb_array_length(options) > 10 THEN
        RETURN FALSE;
    END IF;
    
    -- Check each option is a non-empty string
    FOR i IN 0..jsonb_array_length(options)-1 LOOP
        IF jsonb_typeof(options->i) != 'string' OR length(options->>i) < 1 OR length(options->>i) > 200 THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Add constraint to validate poll options
ALTER TABLE polls ADD CONSTRAINT check_valid_options CHECK (validate_poll_options(options));

-- Grant necessary permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON polls TO authenticated;
GRANT SELECT, INSERT, DELETE ON votes TO authenticated;
GRANT EXECUTE ON FUNCTION validate_poll_options(JSONB) TO authenticated;

-- Comments for documentation
COMMENT ON TABLE polls IS 'Stores user-created polls with questions and multiple choice options';
COMMENT ON TABLE votes IS 'Stores individual votes cast on polls';
COMMENT ON COLUMN polls.options IS 'JSONB array of poll option strings';
COMMENT ON COLUMN polls.settings IS 'JSONB object for poll configuration (allow_multiple_votes, etc.)';
COMMENT ON COLUMN votes.option_index IS 'Index of the selected option in the polls.options array';
COMMENT ON FUNCTION validate_poll_options IS 'Validates that poll options are properly formatted';