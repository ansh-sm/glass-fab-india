-- GLASS FAB INDIA - Enterprise Database Schema
-- Compatible with Supabase & PostgreSQL 14+
-- Implements Row Level Security (RLS) for data protection

CREATE TABLE IF NOT EXISTS public.project_inquiries (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  reference_id TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
  contact_person TEXT NOT NULL,
  company_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  project_type TEXT NOT NULL,
  site_location TEXT,
  scope_sqft TEXT,
  timeline TEXT,
  project_brief TEXT,
  client_ip_hash TEXT,
  status TEXT DEFAULT 'pending_review' CHECK (status IN ('pending_review', 'under_evaluation', 'boq_requested', 'contacted', 'closed')),
  notes TEXT
);

-- Indexes for rapid lookup by reference ID and status
CREATE INDEX IF NOT EXISTS idx_inquiries_ref ON public.project_inquiries(reference_id);
CREATE INDEX IF NOT EXISTS idx_inquiries_status ON public.project_inquiries(status);
CREATE INDEX IF NOT EXISTS idx_inquiries_created_at ON public.project_inquiries(created_at DESC);

-- Enable Row Level Security (RLS)
ALTER TABLE public.project_inquiries ENABLE ROW LEVEL SECURITY;

-- Security Policy: Prevent public read access (protects commercial client data & leads)
CREATE POLICY "Deny public read access to inquiries" 
ON public.project_inquiries 
FOR SELECT 
TO anon 
USING (false);

-- Security Policy: Allow anonymous submission through the validated API handler
CREATE POLICY "Allow validated API insert" 
ON public.project_inquiries 
FOR INSERT 
TO anon 
WITH CHECK (true);

-- Security Policy: Authenticated admin / estimation team full access
CREATE POLICY "Allow authenticated staff full access" 
ON public.project_inquiries 
FOR ALL 
TO authenticated 
USING (true) 
WITH CHECK (true);
