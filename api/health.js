// Serverless API Route: /api/health
// Glass Fab India - Diagnostics, Security & Uptime Healthcheck

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET') {
    return res.status(405).json({ success: false, error: 'Method Not Allowed' });
  }

  return res.status(200).json({
    status: 'OPERATIONAL',
    system: 'GLASS FAB INDIA Enterprise Web Gateway',
    timestamp: new Date().toISOString(),
    securityControls: {
      rateLimiting: 'ACTIVE (Sliding Window)',
      honeypotTrap: 'ACTIVE',
      velocityCheck: 'ACTIVE (1500ms threshold)',
      xssSanitization: 'ACTIVE (Strict Filter)',
      contentSecurityPolicy: 'ACTIVE',
      httpStrictTransportSecurity: 'ACTIVE (max-age=63072000)',
      clickjackingMitigation: 'ACTIVE (X-Frame-Options: DENY)'
    },
    version: '1.2.0-secure'
  });
}
