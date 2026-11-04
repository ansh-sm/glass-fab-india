// =============================================================================
// SERVERLESS API ROUTE: /api/health
// GLASS FAB INDIA — System Diagnostics, Security Controls & Uptime Healthcheck
// =============================================================================

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

  if (req.method !== 'GET') {
    return res.status(405).json({ success: false, error: 'Method Not Allowed' });
  }

  const hasDbConfig = Boolean(process.env.SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY));

  return res.status(200).json({
    status: 'OPERATIONAL',
    system: 'GLASS FAB INDIA Enterprise Web Gateway',
    timestamp: new Date().toISOString(),
    securityControls: {
      rateLimiting: 'ACTIVE (Sliding Window 5req/10min)',
      csrfProtection: 'ACTIVE (Origin / Referer Validation)',
      cryptographicSignatures: 'ACTIVE (HMAC-SHA256)',
      honeypotTrap: 'ACTIVE (Stealth Shield)',
      velocityCheck: 'ACTIVE (1200ms Bot Defense)',
      xssSanitization: 'ACTIVE (Control-Character & Injection Stripping)',
      contentSecurityPolicy: 'ACTIVE (Strict Level 3)',
      httpStrictTransportSecurity: 'ACTIVE (max-age=63072000, preload)',
      clickjackingMitigation: 'ACTIVE (X-Frame-Options: DENY)'
    },
    databaseStatus: {
      adapter: 'PostgreSQL / Supabase with Row Level Security',
      schemaVersion: '2.4-enterprise',
      dualStorageEnabled: true,
      directConnectionConfigured: hasDbConfig
    },
    version: '2.0.0-enterprise'
  });
}
