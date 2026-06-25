const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

mongoose.connect(process.env.MONGO_URI || '')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err.message));

// ── MODELS ────────────────────────────────────────────────────────────────────

const featureSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
  enabled: { type: Boolean, default: true }
});
const Feature = mongoose.model('Feature', featureSchema);

const botStatusSchema = new mongoose.Schema({
  key:          { type: String, default: 'bot', unique: true },
  lastSeen:     { type: Date,   default: null },
  guildCount:   { type: Number, default: 0 },
  groqCalls:    { type: Number, default: 0 },
  commandCount: { type: Number, default: 0 },
  botTag:       { type: String, default: '' },
  botAvatarUrl: { type: String, default: null }
});
const BotStatus = mongoose.model('BotStatus', botStatusSchema);

const allowedUserSchema = new mongoose.Schema({
  discordId: { type: String, unique: true, required: true }
});
const AllowedUser = mongoose.model('allowed_users', allowedUserSchema);

const dashboardUserSchema = new mongoose.Schema({
  username:     { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true }
});
const DashboardUser = mongoose.model('dashboard_users', dashboardUserSchema);

const pending2faSchema = new mongoose.Schema({
  discordId: { type: String, required: true },
  code:      { type: String, required: true },
  expiresAt: { type: Date,   required: true }
});
const Pending2FA = mongoose.model('pending_2fa', pending2faSchema);

const botLoginCodeSchema = new mongoose.Schema({
  discordId:       { type: String, required: true, unique: true },
  discordUsername: { type: String, required: true },
  code:            { type: String, required: true },
  expiresAt:       { type: Date,   required: true }
});
const BotLoginCode = mongoose.model('bot_login_codes', botLoginCodeSchema);

const tempCredSchema = new mongoose.Schema({
  discordId:    { type: String, required: true, unique: true },
  username:     { type: String, required: true },
  passwordHash: { type: String, required: true },
  expiresAt:    { type: Date,   required: true }
});
const TempCredential = mongoose.model('temp_credentials', tempCredSchema);

// ── FEATURE SEED ──────────────────────────────────────────────────────────────

const FEATURES = [
  // Music & Audio
  'music', 'radio', 'youtube', 'karaoke', 'voice_tts', 'shazam', 'suno',
  // AI
  'ai_chat', 'ai_battle', 'image_generation', 'conspiracy',
  // Games
  'trivia', 'connect4', 'minesweeper', 'geoguessr', 'blindtest', 'guesslogo',
  // Social
  'food', 'quests'
];

async function ensureFeatures() {
  for (const name of FEATURES) {
    await Feature.updateOne({ name }, { $setOnInsert: { name, enabled: true } }, { upsert: true });
  }
}
mongoose.connection.once('open', ensureFeatures);

// ── HELPERS ───────────────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const secret = process.env.JWT_SECRET;
  if (!secret) return res.status(500).json({ error: 'Server misconfigured' });
  try {
    req.user = jwt.verify(token, secret);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalid or expired' });
  }
}

function issueToken() {
  return jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '30m' });
}

async function sendDiscordDM(discordId, embed) {
  const botToken = process.env.DISCORD_BOT_TOKEN;
  if (!botToken) throw new Error('DISCORD_BOT_TOKEN not configured');

  const dmRes = await fetch('https://discord.com/api/v10/users/@me/channels', {
    method: 'POST',
    headers: { 'Authorization': `Bot ${botToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient_id: discordId })
  });
  if (!dmRes.ok) throw new Error('Failed to open DM channel');
  const { id: channelId } = await dmRes.json();

  const msgRes = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
    method: 'POST',
    headers: { 'Authorization': `Bot ${botToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ embeds: [embed] })
  });
  if (!msgRes.ok) throw new Error('Failed to send DM');
}

async function send2faDM(discordId, code) {
  return sendDiscordDM(discordId, {
    color: 0x7c3aed,
    title: '🔐 MaximeGPT Dashboard — 2FA Code',
    description: `Your login code is:\n\n# \`${code}\`\n\nThis code expires in **5 minutes**. Do not share it.`,
    footer: { text: 'MaximeGPT Admin Dashboard' }
  });
}

// ── RATE LIMITERS ─────────────────────────────────────────────────────────────

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many failed attempts. Try again in 15 minutes.' }
});

const discordAuthLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: { error: 'Too many requests.' }
});

// ── AUTH: USERNAME / PASSWORD ─────────────────────────────────────────────────

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

  const secret = process.env.JWT_SECRET;
  if (!secret) return res.status(503).json({ error: 'Dashboard not configured.' });

  try {
    let valid = false;

    // Check permanent dashboard users
    const user = await DashboardUser.findOne({ username });
    if (user) {
      valid = await bcrypt.compare(password, user.passwordHash);
    }

    // Fall back to bot login codes (!dashboard admin in Discord)
    if (!valid) {
      const botCode = await BotLoginCode.findOne({
        discordUsername: username,
        code: password,
        expiresAt: { $gt: new Date() }
      });
      if (botCode) {
        valid = true;
        await BotLoginCode.deleteOne({ _id: botCode._id });
      }
    }

    // Fall back to temporary credentials
    if (!valid) {
      const temp = await TempCredential.findOne({ username, expiresAt: { $gt: new Date() } });
      if (temp) {
        valid = await bcrypt.compare(password, temp.passwordHash);
        if (valid) await TempCredential.deleteOne({ _id: temp._id });
      }
    }

    if (!valid) return res.status(401).json({ error: 'Invalid or expired code.' });

    return res.json({ token: issueToken() });
  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ── AUTH: ONE-TIME SETUP ──────────────────────────────────────────────────────

app.post('/api/setup-admin', async (req, res) => {
  const count = await DashboardUser.countDocuments();
  if (count > 0) return res.status(403).json({ error: 'Setup already completed.' });

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const passwordHash = await bcrypt.hash(password, 12);
  await DashboardUser.create({ username, passwordHash });
  res.json({ ok: true, message: `Admin user "${username}" created. This route is now disabled.` });
});

// ── AUTH: DISCORD OAUTH2 ──────────────────────────────────────────────────────

app.get('/api/auth/discord', (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  if (!clientId || !redirectUri) return res.status(503).send('Discord OAuth not configured.');

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'identify'
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/api/auth/discord/callback', discordAuthLimiter, async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/dashboard?error=no_code');

  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  const jwtSecret = process.env.JWT_SECRET;

  if (!clientId || !clientSecret || !redirectUri || !jwtSecret) {
    return res.redirect('/dashboard?error=misconfigured');
  }

  try {
    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri
      })
    });
    if (!tokenRes.ok) return res.redirect('/dashboard?error=token_exchange');
    const { access_token } = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    if (!userRes.ok) return res.redirect('/dashboard?error=user_fetch');
    const { id: discordId, username, avatar } = await userRes.json();

    const allowed = await AllowedUser.findOne({ discordId });
    if (!allowed) return res.redirect('/dashboard?error=not_allowed');

    const code2fa = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await Pending2FA.deleteMany({ discordId });
    await Pending2FA.create({ discordId, code: code2fa, expiresAt });

    await send2faDM(discordId, code2fa);

    const tempToken = jwt.sign(
      { discordId, username, avatar, type: 'pending_2fa' },
      jwtSecret,
      { expiresIn: '5m' }
    );

    res.redirect(`/dashboard?step=2fa&state=${encodeURIComponent(tempToken)}`);
  } catch (err) {
    console.error('Discord OAuth error:', err.message);
    res.redirect('/dashboard?error=server_error');
  }
});

app.post('/api/auth/discord/verify', discordAuthLimiter, async (req, res) => {
  const { state, code } = req.body;
  const jwtSecret = process.env.JWT_SECRET;
  if (!state || !code || !jwtSecret) return res.status(400).json({ error: 'Missing fields.' });

  let payload;
  try {
    payload = jwt.verify(state, jwtSecret);
  } catch {
    return res.status(401).json({ error: 'Session expired. Please login again.' });
  }

  if (payload.type !== 'pending_2fa') return res.status(401).json({ error: 'Invalid session.' });

  const pending = await Pending2FA.findOne({ discordId: payload.discordId });
  if (!pending) return res.status(401).json({ error: 'No pending 2FA. Please login again.' });
  if (new Date() > pending.expiresAt) {
    await Pending2FA.deleteOne({ _id: pending._id });
    return res.status(401).json({ error: 'Code expired. Please login again.' });
  }
  if (pending.code !== String(code).trim()) {
    return res.status(401).json({ error: 'Invalid code.' });
  }

  await Pending2FA.deleteOne({ _id: pending._id });
  return res.json({ token: issueToken() });
});

// ── PROTECTED API ─────────────────────────────────────────────────────────────

app.get('/api/stats', authMiddleware, async (req, res) => {
  const features = await Feature.find({}, { _id: 0, enabled: 1 });
  const enabledCount = features.filter(f => f.enabled).length;
  const totalCount = features.length;
  const uptimeSeconds = Math.floor(process.uptime());

  const doc = await BotStatus.findOne({ key: 'bot' });
  const botOnline = !!(doc && doc.lastSeen && (Date.now() - doc.lastSeen.getTime() < 2 * 60 * 1000));

  res.json({
    enabledCount,
    totalCount,
    uptimeSeconds,
    botOnline,
    guildCount:   doc?.guildCount   || 0,
    groqCalls:    doc?.groqCalls    || 0,
    commandCount: doc?.commandCount || 0,
    botTag:       doc?.botTag       || '',
    botAvatarUrl: doc?.botAvatarUrl || null
  });
});

app.get('/api/features', authMiddleware, async (req, res) => {
  const features = await Feature.find({}, { _id: 0, name: 1, enabled: 1 });
  res.json(features);
});

app.post('/api/features/:name', authMiddleware, async (req, res) => {
  const { name } = req.params;
  if (!FEATURES.includes(name)) return res.status(404).json({ error: 'Unknown feature.' });
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be boolean.' });
  await Feature.updateOne({ name }, { enabled });
  res.json({ ok: true, name, enabled });
});

app.get('/api/status', authMiddleware, async (req, res) => {
  const doc = await BotStatus.findOne({ key: 'bot' });
  const online = !!(doc && doc.lastSeen && (Date.now() - doc.lastSeen.getTime() < 2 * 60 * 1000));
  res.json({ online, lastSeen: doc?.lastSeen || null });
});

// Bot sends a heartbeat every ~60s with its live stats
app.post('/api/bot-heartbeat', async (req, res) => {
  const secret = process.env.JWT_SECRET;
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token || !secret) return res.status(401).json({ error: 'Unauthorized' });
  try { jwt.verify(token, secret); } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const { guildCount, groqCalls, commandCount, botTag, botAvatarUrl } = req.body || {};

  const update = { lastSeen: new Date() };
  if (typeof guildCount   === 'number') update.guildCount   = guildCount;
  if (typeof groqCalls    === 'number') update.groqCalls    = groqCalls;
  if (typeof commandCount === 'number') update.commandCount = commandCount;
  if (typeof botTag       === 'string') update.botTag       = botTag;
  if (botAvatarUrl !== undefined)       update.botAvatarUrl = botAvatarUrl;

  await BotStatus.updateOne({ key: 'bot' }, { $set: update }, { upsert: true });
  res.json({ ok: true });
});

// ── BOT COMMAND: !dashboard admin ────────────────────────────────────────────
// Called by the Discord bot when an admin runs !dashboard admin
app.post('/api/bot-command/dashboard', async (req, res) => {
  const secret = process.env.JWT_SECRET;
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token || !secret || token !== secret) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { discordId, discordUsername, isAdmin, isOwner } = req.body || {};
  if (!discordId || !discordUsername) return res.status(400).json({ error: 'Missing fields.' });
  if (!isAdmin && !isOwner) return res.status(403).json({ error: 'Admin or server owner required.' });

  // Generate a 10-char temporary password
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$';
  let tempPwd = '';
  for (let i = 0; i < 10; i++) tempPwd += chars[Math.floor(Math.random() * chars.length)];

  const passwordHash = await bcrypt.hash(tempPwd, 10);
  const expiresAt    = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  await TempCredential.findOneAndUpdate(
    { discordId },
    { discordId, username: discordUsername, passwordHash, expiresAt },
    { upsert: true, new: true }
  );

  // Send credentials via Discord DM from the bot token
  const dashUrl = process.env.DASHBOARD_URL ||
    `https://${req.headers.host || 'your-dashboard.replit.app'}`;
  try {
    await sendDiscordDM(discordId, {
      color: 0x7c3aed,
      title: '🔐 MaximeGPT Dashboard — Temporary Access',
      description:
        `Here are your dashboard login credentials:\n\n` +
        `**Username:** \`${discordUsername}\`\n` +
        `**Password:** \`${tempPwd}\`\n\n` +
        `[📊 Open Dashboard](${dashUrl}/dashboard)\n\n` +
        `⚠️ These credentials expire in **15 minutes** and can only be used once.`,
      footer: { text: 'MaximeGPT Admin Dashboard' }
    });
  } catch (err) {
    return res.status(500).json({ error: `Failed to send DM: ${err.message}` });
  }

  return res.json({ ok: true });
});


// ── STATIC + CATCH-ALL ────────────────────────────────────────────────────────

function noCache(res) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
}

app.get('/dashboard', (req, res) => {
  noCache(res);
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.use(express.static(path.join(__dirname)));

app.get('/{*splat}', (req, res) => {
  noCache(res);
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`MaximeGPT site running on port ${PORT}`);
});

