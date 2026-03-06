import { WebSocketServer } from "ws";
import { createServer } from "http";

const PORT = process.env.PORT || 3001;

// ─── HTTP server (for health checks + WebSocket upgrade) ───
const httpServer = createServer((req, res) => {
  // CORS preflight
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      status: "ok",
      rooms: rooms.size,
      connections: wss.clients.size,
      uptime: process.uptime(),
    }));
  }

  if (req.url === "/") {
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end(`
      <html>
        <body style="font-family:system-ui;background:#000;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
          <div style="text-align:center">
            <h1>Veil Relay Server</h1>
            <p style="color:#8E8E93">WebSocket relay for Veil demo</p>
            <p style="color:#30D158">● Online</p>
          </div>
        </body>
      </html>
    `);
  }

  res.writeHead(404);
  res.end("Not found");
});

// ─── WebSocket server ───
const wss = new WebSocketServer({ server: httpServer });

// Room management: roomId → Set<ws>
const rooms = new Map();

// User metadata: ws → { roomId, userId, displayName }
const users = new WeakMap();

function broadcast(roomId, message, excludeWs = null) {
  const room = rooms.get(roomId);
  if (!room) return;
  const payload = JSON.stringify(message);
  for (const client of room) {
    if (client !== excludeWs && client.readyState === 1) {
      client.send(payload);
    }
  }
}

function generateUserId() {
  return Math.random().toString(36).slice(2, 10);
}

wss.on("connection", (ws) => {
  let heartbeat = setInterval(() => {
    if (ws.readyState === 1) ws.ping();
  }, 30000);

  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }

    switch (msg.type) {
      // ─── Join a room ───
      case "join": {
        const roomId = (msg.roomId || "default").toLowerCase().trim();
        const displayName = msg.displayName || "Anonymous";
        const userId = generateUserId();

        // Leave any existing room
        const prev = users.get(ws);
        if (prev) {
          const oldRoom = rooms.get(prev.roomId);
          if (oldRoom) {
            oldRoom.delete(ws);
            if (oldRoom.size === 0) rooms.delete(prev.roomId);
            else broadcast(prev.roomId, { type: "user_left", userId: prev.userId, displayName: prev.displayName });
          }
        }

        // Join new room
        if (!rooms.has(roomId)) rooms.set(roomId, new Set());
        rooms.get(roomId).add(ws);
        users.set(ws, { roomId, userId, displayName });

        // Send confirmation
        ws.send(JSON.stringify({
          type: "joined",
          roomId,
          userId,
          displayName,
          peers: Array.from(rooms.get(roomId))
            .filter(c => c !== ws)
            .map(c => {
              const u = users.get(c);
              return u ? { userId: u.userId, displayName: u.displayName } : null;
            })
            .filter(Boolean),
        }));

        // Notify others
        broadcast(roomId, { type: "user_joined", userId, displayName }, ws);
        break;
      }

      // ─── Chat message ───
      case "message": {
        const user = users.get(ws);
        if (!user) return;
        broadcast(user.roomId, {
          type: "message",
          userId: user.userId,
          displayName: user.displayName,
          text: msg.text,
          timestamp: Date.now(),
        }, ws);
        break;
      }

      // ─── Typing indicator ───
      case "typing": {
        const user = users.get(ws);
        if (!user) return;
        broadcast(user.roomId, {
          type: "typing",
          userId: user.userId,
          displayName: user.displayName,
          isTyping: msg.isTyping,
        }, ws);
        break;
      }

      // ─── Payment notification ───
      case "payment": {
        const user = users.get(ws);
        if (!user) return;
        broadcast(user.roomId, {
          type: "payment",
          userId: user.userId,
          displayName: user.displayName,
          amount: msg.amount,
          currency: msg.currency,
          memo: msg.memo,
          timestamp: Date.now(),
        }, ws);
        break;
      }
    }
  });

  ws.on("close", () => {
    clearInterval(heartbeat);
    const user = users.get(ws);
    if (user) {
      const room = rooms.get(user.roomId);
      if (room) {
        room.delete(ws);
        if (room.size === 0) rooms.delete(user.roomId);
        else broadcast(user.roomId, { type: "user_left", userId: user.userId, displayName: user.displayName });
      }
    }
  });

  ws.on("error", () => {
    clearInterval(heartbeat);
  });
});

httpServer.listen(PORT, () => {
  console.log(`Veil relay server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});
