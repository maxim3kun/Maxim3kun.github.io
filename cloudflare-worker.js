/**
 * MaximeGPT — Cloudflare Worker (contact form proxy)
 *
 * Variables d'environnement à configurer dans Cloudflare :
 *   DISCORD_WEBHOOK_URL  — l'URL complète de ton webhook Discord
 *   ALLOWED_ORIGIN       — ton domaine ex: https://www.maximegpt.com
 *
 * Pour déployer :
 *   1. Va sur https://workers.cloudflare.com
 *   2. Crée un nouveau Worker, colle ce code
 *   3. Dans Settings > Variables, ajoute DISCORD_WEBHOOK_URL et ALLOWED_ORIGIN
 *   4. Note l'URL du Worker (ex: https://maximegpt-contact.ton-compte.workers.dev)
 *   5. Remplace WORKER_URL dans index.html par cette URL
 */

const RATE_LIMIT_WINDOW = 3600000; // 1 heure en ms
const RATE_LIMIT_MAX    = 3;       // max 3 messages par IP par heure

// Stockage simple en mémoire (réinitialisé si le Worker redémarre)
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || [];
  const recent = entry.filter(ts => now - ts < RATE_LIMIT_WINDOW);
  if (recent.length >= RATE_LIMIT_MAX) return false;
  recent.push(now);
  rateLimitMap.set(ip, recent);
  return true;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = env.ALLOWED_ORIGIN || '';

    const corsHeaders = {
      'Access-Control-Allow-Origin': allowed,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Réponse aux preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Rejette si l'origine n'est pas autorisée
    if (origin !== allowed) {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Rate limit par IP
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!checkRateLimit(ip)) {
      return new Response(JSON.stringify({ error: 'Too many requests' }), {
        status: 429,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Lecture et validation du corps
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { name, message, lang } = body;
    if (!name || !message) {
      return new Response(JSON.stringify({ error: 'Missing fields' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Nettoyage anti-mention Discord
    const safe = s => String(s)
      .replace(/@(everyone|here)/gi, '[@$1]')
      .replace(/<@[!&]?\d+>/g, '[mention]');

    // Envoi au webhook Discord
    const webhookUrl = env.DISCORD_WEBHOOK_URL;
    if (!webhookUrl) {
      return new Response(JSON.stringify({ error: 'Not configured' }), {
        status: 503,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const discordRes = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          color: 0x7c3aed,
          title: '📬 Nouveau message — MaximeGPT.com',
          fields: [
            { name: '👤 Discord', value: safe(name).slice(0, 256), inline: true },
            { name: '🌐 Langue',  value: (lang || 'en').toUpperCase(), inline: true },
            { name: '💬 Message', value: safe(message).slice(0, 1000) },
          ],
          footer: { text: `maximegpt.com · ${new Date().toUTCString()}` },
        }],
      }),
    });

    if (discordRes.ok || discordRes.status === 204) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ error: 'Webhook failed' }), {
      status: 502,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  },
};
