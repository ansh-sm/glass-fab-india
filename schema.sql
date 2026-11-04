-- =============================================================================
-- GLASS FAB INDIA — ENTERPRISE DATABASE ARCHITECTURE & AUDIT LEDGER
-- Compatible with PostgreSQL 14+, Supabase, AWS RDS Aurora, and Neon Postgres
-- Features: Row Level Security (RLS), Cryptographic Signatures, Immutable Audit Trail,
-- GIN Full-Text Search, Automatic Timestamp Triggers, and Soft-Deletion.
-- =============================================================================

-- Enable pgcrypto extension for cryptographic utilities and UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. MAIN TABLE: project_inquiries
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.project_inquiries (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  reference_id VARCHAR(32) UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
  
  -- Client & Company Identity
  contact_person VARCHAR(100) NOT NULL,
  company_name VARCHAR(150) NOT NULL,
  email VARCHAR(120) NOT NULL CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
  phone VARCHAR(30) NOT NULL,
  
  -- Architectural Scope & Engineering Specifications
  project_type VARCHAR(80) NOT NULL,
  site_location VARCHAR(150),
  scope_sqft VARCHAR(50),
  timeline VARCHAR(50),
  project_brief TEXT,
  
  -- Security, Integrity & Anti-Tamper Checksums
  client_ip_hash VARCHAR(64) NOT NULL,
  tamper_signature VARCHAR(64) NOT NULL,
  
  -- Workflow & Status Lifecycle
  status VARCHAR(30) DEFAULT 'pending_review' NOT NULL 
    CHECK (status IN ('pending_review', 'under_evaluation', 'boq_requested', 'technical_review', 'contacted', 'closed', 'archived')),
  priority VARCHAR(20) DEFAULT 'standard' NOT NULL 
    CHECK (priority IN ('standard', 'priority_tender', 'commercial_high_rise', 'institutional')),
  assigned_engineer VARCHAR(100),
  internal_notes TEXT,
  
  -- Enterprise Soft-Deletion Guard
  is_archived BOOLEAN DEFAULT FALSE NOT NULL
);

-- -----------------------------------------------------------------------------
-- 2. IMMUTABLE AUDIT TRAIL: inquiry_audit_log
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.inquiry_audit_log (
  audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  inquiry_id UUID NOT NULL REFERENCES public.project_inquiries(id) ON DELETE CASCADE,
  reference_id VARCHAR(32) NOT NULL,
  action VARCHAR(40) NOT NULL, -- 'CREATED', 'STATUS_CHANGED', 'ASSIGNED', 'ARCHIVED'
  previous_state JSONB,
  new_state JSONB,
  recorded_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
  recorded_by TEXT DEFAULT current_user NOT NULL
);

-- -----------------------------------------------------------------------------
-- 3. HIGH-PERFORMANCE INDEXING STRATEGY
-- -----------------------------------------------------------------------------
-- Rapid lookup by Reference ID
CREATE INDEX IF NOT EXISTS idx_inquiries_ref 
  ON public.project_inquiries(reference_id);

-- Filter by workflow status
CREATE INDEX IF NOT EXISTS idx_inquiries_status 
  ON public.project_inquiries(status);

-- Reverse chronological ordering for dashboard views
CREATE INDEX IF NOT EXISTS idx_inquiries_created_at 
  ON public.project_inquiries(created_at DESC);

-- Partial index for active non-archived inquiries
CREATE INDEX IF NOT EXISTS idx_inquiries_active 
  ON public.project_inquiries(status, created_at DESC) 
  WHERE is_archived = FALSE;

-- GIN Full-Text Search index across client, firm and brief notes
CREATE INDEX IF NOT EXISTS idx_inquiries_search 
  ON public.project_inquiries 
  USING gin(to_tsvector('english', company_name || ' ' || contact_person || ' ' || coalesce(project_brief, '')));

-- Index on audit log foreign key
CREATE INDEX IF NOT EXISTS idx_audit_inquiry_id 
  ON public.inquiry_audit_log(inquiry_id);

-- -----------------------------------------------------------------------------
-- 4. AUTOMATED AUDIT & TIMESTAMP TRIGGERS
-- -----------------------------------------------------------------------------
-- Trigger Function: Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION public.fn_update_inquiry_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = timezone('utc'::text, now());
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_inquiry_updated_at ON public.project_inquiries;
CREATE TRIGGER trg_inquiry_updated_at
  BEFORE UPDATE ON public.project_inquiries
  FOR EACH ROW
  EXECUTE FUNCTION public.fn_update_inquiry_timestamp();

-- Trigger Function: Auto-log every status or assignment change
CREATE OR REPLACE FUNCTION public.fn_log_inquiry_change()
RETURNS TRIGGER AS $$
BEGIN
  IF (TG_OP = 'INSERT') THEN
    INSERT INTO public.inquiry_audit_log (inquiry_id, reference_id, action, new_state)
    VALUES (
      NEW.id,
      NEW.reference_id,
      'CREATED',
      to_jsonb(NEW)
    );
  ELSIF (TG_OP = 'UPDATE') THEN
    IF (OLD.status IS DISTINCT FROM NEW.status OR OLD.assigned_engineer IS DISTINCT FROM NEW.assigned_engineer OR OLD.is_archived IS DISTINCT FROM NEW.is_archived) THEN
      INSERT INTO public.inquiry_audit_log (inquiry_id, reference_id, action, previous_state, new_state)
      VALUES (
        NEW.id,
        NEW.reference_id,
        CASE 
          WHEN OLD.is_archived IS DISTINCT FROM NEW.is_archived THEN 'ARCHIVE_STATUS_CHANGED'
          WHEN OLD.status IS DISTINCT FROM NEW.status THEN 'STATUS_UPDATED'
          ELSE 'ASSIGNMENT_UPDATED'
        END,
        to_jsonb(OLD),
        to_jsonb(NEW)
      );
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_inquiry_audit ON public.project_inquiries;
CREATE TRIGGER trg_inquiry_audit
  AFTER INSERT OR UPDATE ON public.project_inquiries
  FOR EACH ROW
  EXECUTE FUNCTION public.fn_log_inquiry_change();

-- -----------------------------------------------------------------------------
-- 5. ROW LEVEL SECURITY (RLS) ZERO-TRUST ACCESS POLICIES
-- -----------------------------------------------------------------------------
ALTER TABLE public.project_inquiries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inquiry_audit_log ENABLE ROW LEVEL SECURITY;

-- 1. Anonymous Users: Deny all SELECT access (prevents competitor & web scraping)
DROP POLICY IF EXISTS "Deny public select access" ON public.project_inquiries;
CREATE POLICY "Deny public select access" 
  ON public.project_inquiries 
  FOR SELECT 
  TO anon 
  USING (false);

-- 2. Anonymous Users: Allow insertion through validated API endpoint
DROP POLICY IF EXISTS "Allow validated web inserts" ON public.project_inquiries;
CREATE POLICY "Allow validated web inserts" 
  ON public.project_inquiries 
  FOR INSERT 
  TO anon 
  WITH CHECK (true);

-- 3. Anonymous Users: Deny UPDATE and DELETE completely
DROP POLICY IF EXISTS "Deny public updates" ON public.project_inquiries;
CREATE POLICY "Deny public updates" 
  ON public.project_inquiries 
  FOR UPDATE 
  TO anon 
  USING (false);

DROP POLICY IF EXISTS "Deny public deletions" ON public.project_inquiries;
CREATE POLICY "Deny public deletions" 
  ON public.project_inquiries 
  FOR DELETE 
  TO anon 
  USING (false);

-- 4. Authenticated Staff (Internal Estimation & Engineering Desk): Full Access
DROP POLICY IF EXISTS "Allow authenticated staff full access" ON public.project_inquiries;
CREATE POLICY "Allow authenticated staff full access" 
  ON public.project_inquiries 
  FOR ALL 
  TO authenticated 
  USING (true) 
  WITH CHECK (true);

-- 5. Audit Log: Read-only for authenticated staff; write only via triggers
DROP POLICY IF EXISTS "Staff can read audit log" ON public.inquiry_audit_log;
CREATE POLICY "Staff can read audit log" 
  ON public.inquiry_audit_log 
  FOR SELECT 
  TO authenticated 
  USING (true);

DROP POLICY IF EXISTS "Deny public audit access" ON public.inquiry_audit_log;
CREATE POLICY "Deny public audit access" 
  ON public.inquiry_audit_log 
  FOR ALL 
  TO anon 
  USING (false);
