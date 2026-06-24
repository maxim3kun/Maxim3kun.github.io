const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

mongoose.connect(process.env.DATABASE_URL || '')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err.message));

const featureSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
  enabled: { type: Boolean, default: true }
});
const Feature = mongoose.model('Feature', featureSchema);

const botStatusSchema = new mongoose.Schema({
  key: { type: String, default: 'bot', unique: true },
  lastSeen: { type: Date, default: null }
});
const BotStatus = mongoose.model('BotStatus', botStatusSchema);

const FEATURES = [
  'music', 'radio', 'youtube', 'karaoke', 'voice_tts',
  'ai_chat', 'ai_battle', 'trivia', 'connect4', 'minesweeper',
  'geoguessr', 'blindtest', 'image_generation', 'conspiracy'
];

async function ensureFeatures() {
  for (const name of FEATURES) {
    await Feature.updateOne({ name }, { $setOnInsert: { name, enabled: true } }, { upsert: true });
  }
}
mongoose.connection.once('open', ensureFeatures);

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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many failed attempts. Try again in 15 minutes.' }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required.' });

  const hash = process.env.DASHBOARD_PASSWORD_HASH;
  const secret = process.env.JWT_SECRET;
  if (!hash || !secret) return res.status(503).json({ error: 'Dashboard not configured.' });

  const valid = await bcrypt.compare(password, hash);
  if (!valid) return res.status(401).json({ error: 'Invalid password.' });

  const token = jwt.sign({ role: 'admin' }, secret, { expiresIn: '30m' });
  return res.json({ token });
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
  const online = doc && doc.lastSeen && (Date.now() - doc.lastSeen.getTime() < 2 * 60 * 1000);
  res.json({ online: !!online, lastSeen: doc?.lastSeen || null });
});

app.post('/api/bot-heartbeat', async (req, res) => {
  const secret = process.env.JWT_SECRET;
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token || !secret) return res.status(401).json({ error: 'Unauthorized' });
  try {
    jwt.verify(token, secret);
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
  await BotStatus.updateOne({ key: 'bot' }, { lastSeen: new Date() }, { upsert: true });
  res.json({ ok: true });
});

app.post('/api/contact', async (req, res) => {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) {
    return res.status(503).json({ error: 'Contact service not configured.' });
  }

  const { name, message, lang } = req.body;
  if (!name || !message) {
    return res.status(400).json({ error: 'Missing fields.' });
  }

  const safe = s => s.replace(/@(everyone|here)/gi, '[@$1]').replace(/<@[!&]?\d+>/g, '[mention]');

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          color: 0x7c3aed,
          title: '📬 Nouveau message — MaximeGPT.com',
          fields: [
            { name: '👤 Discord', value: safe(name).slice(0, 256), inline: true },
            { name: '🌐 Langue', value: (lang || 'en').toUpperCase(), inline: true },
            { name: '💬 Message', value: safe(message).slice(0, 1000) },
          ],
          footer: { text: `maximegpt.com · ${new Date().toUTCString()}` }
        }]
      })
    });

    if (response.ok || response.status === 204) {
      return res.json({ ok: true });
    }
    return res.status(502).json({ error: 'Webhook failed.' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.use(express.static(path.join(__dirname)));

app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`MaximeGPT site running on port ${PORT}`);
});
