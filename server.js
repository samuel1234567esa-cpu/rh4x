const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const app = express();
app.use(cors());
app.use(express.json());
const db = new Database('keys.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    key TEXT PRIMARY KEY, hours INTEGER NOT NULL, plan TEXT NOT NULL,
    created INTEGER NOT NULL, expires INTEGER NOT NULL,
    used INTEGER DEFAULT 0, usedBy TEXT, usedAt INTEGER
  );
  CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL,
    hwid TEXT NOT NULL, ip TEXT, activatedAt INTEGER NOT NULL
  );
`);
const ADMIN_TOKEN = "rh4x_samuel_2024_xk92mP";
function authAdmin(req, res, next) {
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN)
    return res.status(401).json({ error: 'Não autorizado' });
  next();
}
function genKey() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  const p = () => Array.from({length:4}, () => c[Math.floor(Math.random()*c.length)]).join('');
  const e = Array.from({length:6}, () => c[Math.floor(Math.random()*c.length)]).join('');
  return `RH4X-${p()}-${p()}-${p()}-${e}`;
}
app.post('/api/validate', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.json({ valid: false, message: '❌ Parâmetros inválidos' });
  const row = db.prepare('SELECT * FROM keys WHERE key = ?').get(key);
  if (!row) return res.json({ valid: false, message: '❌ Key inválida' });
  if (row.used) return res.json({ valid: false, message: '❌ Key já utilizada' });
  const now = Math.floor(Date.now() / 1000);
  if (now > row.expires) return res.json({ valid: false, message: '❌ Key expirada' });
  const act = db.prepare('SELECT * FROM activations WHERE key = ?').get(key);
  if (!act) {
    db.prepare('INSERT INTO activations (key, hwid, ip, activatedAt) VALUES (?, ?, ?, ?)')
      .run(key, hwid, req.ip, now);
  } else if (act.hwid !== hwid) {
    return res.json({ valid: false, message: '❌ Key já ativada em outro dispositivo' });
  }
  const left = row.expires - now;
  res.json({ valid: true, message: `✅ Key válida! Restam ${Math.floor(left/3600)}h ${Math.floor((left%3600)/60)}min`, expiresAt: row.expires * 1000 });
});
app.get('/api/keys', authAdmin, (req, res) => res.json(db.prepare('SELECT * FROM keys ORDER BY created DESC').all()));
app.post('/api/keys', authAdmin, (req, res) => {
  const { hours, plan } = req.body;
  if (!hours || hours <= 0) return res.status(400).json({ error: 'Horas inválidas' });
  const key = genKey(), now = Math.floor(Date.now() / 1000), expires = now + (hours * 3600);
  db.prepare('INSERT INTO keys (key, hours, plan, created, expires) VALUES (?, ?, ?, ?, ?)').run(key, hours, plan || `${hours}h`, now, expires);
  res.json({ key, hours, plan, created: now, expires });
});
app.delete('/api/keys/:key', authAdmin, (req, res) => {
  db.prepare('DELETE FROM keys WHERE key = ?').run(req.params.key);
  db.prepare('DELETE FROM activations WHERE key = ?').run(req.params.key);
  res.json({ ok: true });
});
app.delete('/api/keys', authAdmin, (req, res) => {
  db.prepare('DELETE FROM keys').run();
  db.prepare('DELETE FROM activations').run();
  res.json({ ok: true });
});
app.post('/api/keys/:key/use', authAdmin, (req, res) => {
  db.prepare('UPDATE keys SET used = 1, usedAt = ? WHERE key = ?').run(Math.floor(Date.now() / 1000), req.params.key);
  res.json({ ok: true });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ RH4X Backend na porta ${PORT}`));
