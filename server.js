const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

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

app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`MaximeGPT site running on port ${PORT}`);
});
