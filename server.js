require('dotenv').config();
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { WebSocketServer, WebSocket } = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.APP_SECRET || crypto.randomBytes(32).toString('hex');
const TTL = Math.max(30, Number(process.env.PRESENCE_TTL_SECONDS || 75)) * 1000;
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 100 * 1024 * 1024);
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
const clients = new Map(); // connectionId -> { ws, deviceId, ... }
const deviceConnections = new Map(); // deviceId -> connectionId
const history = new Map(); // deviceId -> recent metadata history (in-memory demo persistence)
const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '32kb' }));
// Allow the separately hosted InfinityFree frontend to call the public config API.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(require('path').join(__dirname, 'public'), { extensions: ['html'] }));

function id6() {
  let id;
  do { id = Array.from(crypto.randomBytes(6), b => alphabet[b % alphabet.length]).join(''); }
  while (deviceConnections.has(id));
  return id;
}
function sign(value) { return crypto.createHmac('sha256', SECRET).update(value).digest('hex'); }
function safeSend(ws, data) { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data)); }
function record(deviceId, item) {
  if (!history.has(deviceId)) history.set(deviceId, []);
  const list = history.get(deviceId); list.unshift(item); if (list.length > 100) list.length = 100;
}
function publicDevice(c, viewer) {
  const out = { id: c.deviceId, online: true, lastSeen: c.lastSeen, locationAvailable: Boolean(c.location && c.locationSharing), label: c.label || 'AirPass device' };
  // Never broadcast coordinates. Return only a per-viewer approximate distance, and only when both opted in.
  if (viewer && viewer.locationSharing && viewer.location && c.locationSharing && c.location) {
    const ageA = Date.now() - viewer.location.at, ageB = Date.now() - c.location.at;
    if (ageA < 90000 && ageB < 90000 && viewer.location.accuracy <= 1000 && c.location.accuracy <= 1000) {
      const rad = x => x * Math.PI / 180, R = 6371000;
      const dLat = rad(c.location.lat - viewer.location.lat), dLon = rad(c.location.lon - viewer.location.lon);
      const a = Math.sin(dLat/2)**2 + Math.cos(rad(viewer.location.lat))*Math.cos(rad(c.location.lat))*Math.sin(dLon/2)**2;
      const meters = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
      const uncertainty = viewer.location.accuracy + c.location.accuracy;
      if (uncertainty <= Math.max(500, meters * 2)) out.distanceMeters = Math.round(meters);
      out.distanceAccuracyMeters = Math.round(uncertainty);
    }
  }
  return out;
}
function broadcastPresence() {
  const now = Date.now();
  const active = [...clients.values()].filter(c => c.deviceId && c.discovery && now - c.lastSeen < TTL);
  for (const c of active) safeSend(c.ws, { type: 'presence', devices: active.filter(d => d.deviceId !== c.deviceId).map(d => publicDevice(d, c)), serverTime: now });
}
function cleanStale() {
  const now = Date.now();
  for (const [cid, c] of clients) {
    if (c.deviceId && now - c.lastSeen > TTL) {
      clients.delete(cid);
      if (deviceConnections.get(c.deviceId) === cid) deviceConnections.delete(c.deviceId);
      try { c.ws.close(); } catch {}
    }
  }
  broadcastPresence();
}
setInterval(cleanStale, 15_000).unref();

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'AirPass Nearby', time: new Date().toISOString(), onlineDevices: deviceConnections.size }));
app.get('/api/config', (_req, res) => {
  let iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
  try { if (process.env.ICE_SERVERS_JSON) iceServers = JSON.parse(process.env.ICE_SERVERS_JSON); } catch {}
  res.json({ iceServers, maxFileBytes: MAX_FILE_BYTES, presenceTtlSeconds: TTL / 1000 });
});
app.get('/api/history/:id', (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-z0-9]{6}$/.test(id)) return res.status(400).json({ error: 'Invalid device ID' });
  res.json({ items: history.get(id) || [] });
});

server.on('upgrade', (req, socket, head) => {
  const origin = req.headers.origin;
  let sameOrigin = false; try { sameOrigin = Boolean(origin && new URL(origin).host === req.headers.host); } catch {}
  if (origin && !sameOrigin && !allowedOrigins.includes(origin)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

wss.on('connection', ws => {
  const connectionId = crypto.randomUUID();
  const client = { ws, connectionId, deviceId: null, lastSeen: Date.now(), location: null, label: 'AirPass device', locationSharing: false, discovery: false };
  clients.set(connectionId, client);
  safeSend(ws, { type: 'welcome', connectionId, serverTime: Date.now() });

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return safeSend(ws, { type: 'error', message: 'Invalid message format.' }); }
    if (!msg || typeof msg.type !== 'string') return;
    client.lastSeen = Date.now();

    if (msg.type === 'register') {
      let deviceId = typeof msg.deviceId === 'string' ? msg.deviceId.toLowerCase() : '';
      if (deviceId && !/^[a-z0-9]{6}$/.test(deviceId)) return safeSend(ws, { type: 'error', message: 'Device ID must be six letters or numbers.' });
      if (deviceId && deviceConnections.has(deviceId) && deviceConnections.get(deviceId) !== connectionId) {
        // Existing active ID cannot be claimed by a second live connection.
        deviceId = '';
      }
      if (!deviceId) deviceId = id6();
      client.deviceId = deviceId;
      client.label = typeof msg.label === 'string' ? msg.label.slice(0, 32) : 'AirPass device';
      client.locationSharing = Boolean(msg.locationSharing);
      client.discovery = Boolean(msg.discovery);
      deviceConnections.set(deviceId, connectionId);
      safeSend(ws, { type: 'registered', deviceId, serverTime: Date.now(), token: sign(`${deviceId}:${connectionId}`).slice(0, 32) });
      broadcastPresence();
      return;
    }
    if (!client.deviceId) return safeSend(ws, { type: 'error', message: 'Register this device first.' });
    if (msg.type === 'heartbeat') { if (typeof msg.discovery === 'boolean') client.discovery = msg.discovery; broadcastPresence(); return; }
    if (msg.type === 'location') {
      if (!client.locationSharing || !msg.enabled) { client.location = null; client.locationSharing = false; }
      else {
        const lat = Number(msg.lat), lon = Number(msg.lon), accuracy = Number(msg.accuracy);
        if (Number.isFinite(lat) && lat >= -90 && lat <= 90 && Number.isFinite(lon) && lon >= -180 && lon <= 180 && Number.isFinite(accuracy) && accuracy >= 0 && accuracy <= 10000) {
          // Coordinates remain server-side; only approximate distance is sent to the requesting client.
          client.location = { lat, lon, accuracy, at: Date.now() };
          client.locationSharing = true;
        }
      }
      broadcastPresence(); return;
    }
    if (msg.type === 'pair-request') {
      const target = String(msg.to || '').toLowerCase();
      if (!/^[a-z0-9]{6}$/.test(target) || target === client.deviceId) return safeSend(ws, { type: 'error', message: 'Choose a valid different device.' });
      const targetCid = deviceConnections.get(target), targetClient = clients.get(targetCid);
      if (!targetClient || Date.now() - targetClient.lastSeen > TTL) return safeSend(ws, { type: 'error', message: 'That device is offline. Ask them to enable discovery.' });
      const requestId = crypto.randomUUID();
      safeSend(targetClient.ws, { type: 'pair-incoming', requestId, from: client.deviceId, label: client.label });
      safeSend(ws, { type: 'pair-pending', requestId, to: target });
      return;
    }
    if (msg.type === 'pair-response') {
      const requestId = String(msg.requestId || '');
      const target = String(msg.to || '').toLowerCase();
      const targetClient = clients.get(deviceConnections.get(target));
      if (!targetClient || !requestId) return safeSend(ws, { type: 'error', message: 'Pairing request expired.' });
      safeSend(targetClient.ws, { type: 'pair-result', requestId, from: client.deviceId, accepted: Boolean(msg.accepted) });
      safeSend(ws, { type: 'pair-result', requestId, from: target, accepted: Boolean(msg.accepted) });
      return;
    }
    if (msg.type === 'signal') {
      const target = String(msg.to || '').toLowerCase();
      const targetClient = clients.get(deviceConnections.get(target));
      if (!targetClient || !targetClient.deviceId || !msg.payload || !['offer','answer','ice','transfer-offer','transfer-accepted','transfer-rejected','transfer-done','transfer-failed','cancel','remote-release'].includes(msg.payload.kind)) return safeSend(ws, { type: 'error', message: 'Signal target unavailable or message invalid.' });
      // Forward only WebRTC negotiation/transfer control messages, never arbitrary file contents.
      safeSend(targetClient.ws, { type: 'signal', from: client.deviceId, payload: msg.payload });
      return;
    }
    if (msg.type === 'history') {
      const item = { sessionId: String(msg.sessionId || crypto.randomUUID()), senderId: String(msg.senderId || client.deviceId), recipientId: String(msg.recipientId || ''), grabAt: msg.grabAt || null, releaseAt: msg.releaseAt || null, status: String(msg.status || 'metadata'), result: String(msg.result || ''), at: new Date().toISOString() };
      record(client.deviceId, item); if (item.recipientId) record(item.recipientId, item);
      return;
    }
    if (msg.type === 'disconnect') { client.location = null; client.locationSharing = false; client.discovery = false; safeSend(ws, { type: 'disconnected' }); broadcastPresence(); }
  });
  ws.on('close', () => {
    clients.delete(connectionId);
    if (client.deviceId && deviceConnections.get(client.deviceId) === connectionId) deviceConnections.delete(client.deviceId);
    broadcastPresence();
  });
  ws.on('error', () => {});
});

server.listen(PORT, () => console.log(`AirPass Nearby listening on http://localhost:${PORT}`));
