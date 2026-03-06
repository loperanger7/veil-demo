import { useState, useEffect, useRef, useCallback } from "react";

// ─────────────────────────────────────────────
// VEIL — Live Demo with WebSocket Chat
// Post-Quantum Encrypted Chat & Payments
// ─────────────────────────────────────────────

// Design System
const Colors = {
  bg: "#000000",
  surface: "#1C1C1E",
  surfaceSecondary: "#2C2C2E",
  accent: "#0A84FF",
  accentDim: "rgba(10,132,255,0.15)",
  text: "#FFFFFF",
  textSecondary: "#8E8E93",
  textTertiary: "#636366",
  outgoing: "#0A84FF",
  incoming: "#2C2C2E",
  separator: "rgba(255,255,255,0.08)",
  paymentGradientStart: "#0A84FF",
  paymentGradientEnd: "#BF5AF2",
  green: "#30D158",
  red: "#FF453A",
  orange: "#FF9F0A",
};

// ─── WebSocket hook ───
const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:3001";

function useVeilSocket() {
  const wsRef = useRef(null);
  const [connected, setConnected] = useState(false);
  const [roomId, setRoomId] = useState(null);
  const [userId, setUserId] = useState(null);
  const [displayName, setDisplayName] = useState(null);
  const [peers, setPeers] = useState([]);
  const [messages, setMessages] = useState([]);
  const [remoteTyping, setRemoteTyping] = useState(null);
  const reconnectTimer = useRef(null);
  const handlersRef = useRef({});

  const connect = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState <= 1) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      switch (msg.type) {
        case "joined":
          setRoomId(msg.roomId);
          setUserId(msg.userId);
          setDisplayName(msg.displayName);
          setPeers(msg.peers);
          break;
        case "user_joined":
          setPeers(prev => [...prev.filter(p => p.userId !== msg.userId), { userId: msg.userId, displayName: msg.displayName }]);
          setMessages(prev => [...prev, { id: Date.now(), type: "system", text: `${msg.displayName} joined the room` }]);
          break;
        case "user_left":
          setPeers(prev => prev.filter(p => p.userId !== msg.userId));
          setMessages(prev => [...prev, { id: Date.now(), type: "system", text: `${msg.displayName} left the room` }]);
          setRemoteTyping(null);
          break;
        case "message":
          setMessages(prev => [...prev, {
            id: msg.timestamp,
            type: "chat",
            text: msg.text,
            incoming: true,
            senderName: msg.displayName,
            senderId: msg.userId,
            time: new Date(msg.timestamp).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }),
          }]);
          setRemoteTyping(null);
          break;
        case "typing":
          if (msg.isTyping) {
            setRemoteTyping(msg.displayName);
            // Auto-clear after 3s
            clearTimeout(handlersRef.current.typingTimeout);
            handlersRef.current.typingTimeout = setTimeout(() => setRemoteTyping(null), 3000);
          } else {
            setRemoteTyping(null);
          }
          break;
        case "payment":
          setMessages(prev => [...prev, {
            id: msg.timestamp,
            type: "chat",
            incoming: true,
            senderName: msg.displayName,
            senderId: msg.userId,
            time: new Date(msg.timestamp).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }),
            payment: { amount: msg.amount, currency: msg.currency, memo: msg.memo, status: "complete" },
          }]);
          break;
      }
    };

    ws.onclose = () => {
      setConnected(false);
      // Reconnect after 2s
      reconnectTimer.current = setTimeout(connect, 2000);
    };

    ws.onerror = () => ws.close();
  }, []);

  const disconnect = useCallback(() => {
    clearTimeout(reconnectTimer.current);
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnected(false);
    setRoomId(null);
    setUserId(null);
    setPeers([]);
    setMessages([]);
    setRemoteTyping(null);
  }, []);

  const joinRoom = useCallback((room, name) => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: "join", roomId: room, displayName: name }));
    }
  }, []);

  const sendMessage = useCallback((text) => {
    if (!wsRef.current || wsRef.current.readyState !== 1) return;
    wsRef.current.send(JSON.stringify({ type: "message", text }));
    setMessages(prev => [...prev, {
      id: Date.now(),
      type: "chat",
      text,
      incoming: false,
      time: new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }),
    }]);
  }, []);

  const sendTyping = useCallback((isTyping) => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: "typing", isTyping }));
    }
  }, []);

  const sendPayment = useCallback((amount, currency, memo) => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: "payment", amount, currency, memo }));
      setMessages(prev => [...prev, {
        id: Date.now(),
        type: "chat",
        incoming: false,
        time: new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }),
        payment: { amount, currency, memo, status: "complete" },
      }]);
    }
  }, []);

  useEffect(() => {
    return () => {
      clearTimeout(reconnectTimer.current);
      clearTimeout(handlersRef.current.typingTimeout);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  return { connected, roomId, userId, displayName, peers, messages, remoteTyping, connect, disconnect, joinRoom, sendMessage, sendTyping, sendPayment };
}

// ─── Icons (inline SVG) ───
const IconSend = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" />
  </svg>
);
const IconDollar = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><line x1="12" y1="1" x2="12" y2="23" /><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6" />
  </svg>
);
const IconBack = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={Colors.accent} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="15 18 9 12 15 6" />
  </svg>
);
const IconShield = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
const IconCheck = () => (
  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={Colors.green} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);
const IconLink = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" />
    <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" />
  </svg>
);
const IconCopy = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
  </svg>
);
const IconUsers = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={Colors.textSecondary} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 00-3-3.87" /><path d="M16 3.13a4 4 0 010 7.75" />
  </svg>
);

// ─── JoinScreen ───
function JoinScreen({ onJoin, socket }) {
  const [name, setName] = useState("");
  const [room, setRoom] = useState("");
  const [joining, setJoining] = useState(false);

  const handleJoin = () => {
    if (!name.trim()) return;
    setJoining(true);
    socket.connect();
    // Wait for connection, then join
    const check = setInterval(() => {
      if (socket.connected) {
        clearInterval(check);
        socket.joinRoom(room.trim() || "veil-public", name.trim());
        onJoin();
      }
    }, 100);
    // Timeout after 5s
    setTimeout(() => { clearInterval(check); setJoining(false); }, 5000);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", background: Colors.bg, padding: 32, gap: 24 }}>
      {/* Logo */}
      <div style={{
        width: 80, height: 80, borderRadius: 20,
        background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`,
        display: "flex", alignItems: "center", justifyContent: "center",
        boxShadow: "0 8px 32px rgba(10,132,255,0.3)",
      }}>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      </div>

      <div style={{ textAlign: "center" }}>
        <h1 style={{ color: Colors.text, fontSize: 28, fontWeight: 700, margin: "0 0 6px" }}>Veil</h1>
        <p style={{ color: Colors.textSecondary, fontSize: 14, margin: 0 }}>Post-Quantum Encrypted Chat</p>
      </div>

      <div style={{ width: "100%", maxWidth: 300, display: "flex", flexDirection: "column", gap: 12 }}>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="Your display name"
          onKeyDown={e => e.key === "Enter" && handleJoin()}
          style={{
            width: "100%", padding: "14px 16px", borderRadius: 12,
            border: `1px solid ${Colors.surfaceSecondary}`, background: Colors.surface,
            color: Colors.text, fontSize: 16, outline: "none", boxSizing: "border-box",
          }}
        />
        <input
          value={room}
          onChange={e => setRoom(e.target.value)}
          placeholder="Room code (or leave blank for public)"
          onKeyDown={e => e.key === "Enter" && handleJoin()}
          style={{
            width: "100%", padding: "14px 16px", borderRadius: 12,
            border: `1px solid ${Colors.surfaceSecondary}`, background: Colors.surface,
            color: Colors.text, fontSize: 16, outline: "none", boxSizing: "border-box",
          }}
        />
        <button
          onClick={handleJoin}
          disabled={!name.trim() || joining}
          style={{
            width: "100%", padding: "14px", borderRadius: 12, border: "none", cursor: name.trim() && !joining ? "pointer" : "default",
            background: name.trim() && !joining ? `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})` : Colors.surfaceSecondary,
            color: name.trim() ? "#fff" : Colors.textTertiary,
            fontSize: 17, fontWeight: 600, transition: "all 0.2s",
          }}
        >
          {joining ? "Connecting..." : "Join Chat"}
        </button>
      </div>

      <div style={{ textAlign: "center", marginTop: 8 }}>
        <p style={{ color: Colors.textTertiary, fontSize: 12, margin: 0 }}>
          Share the same room code with a friend to chat live
        </p>
        <p style={{ color: Colors.textTertiary, fontSize: 11, margin: "8px 0 0" }}>
          PQXDH + Triple Ratchet · ML-KEM-1024 · Sealed Sender
        </p>
      </div>
    </div>
  );
}

// ─── RoomHeader ───
function RoomHeader({ roomId, peers, connected, onLeave }) {
  const [copied, setCopied] = useState(false);

  const copyRoom = () => {
    navigator.clipboard?.writeText(roomId).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div style={{
      display: "flex", alignItems: "center", padding: "10px 12px",
      borderBottom: `1px solid ${Colors.separator}`, background: Colors.surface, gap: 8,
    }}>
      <button onClick={onLeave} style={{ background: "none", border: "none", cursor: "pointer", padding: 4, display: "flex", alignItems: "center" }}>
        <IconBack />
      </button>
      <div style={{
        width: 36, height: 36, borderRadius: 18,
        background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <IconUsers />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color: Colors.text, fontWeight: 600, fontSize: 16 }}>#{roomId}</span>
          <button onClick={copyRoom} style={{ background: "none", border: "none", cursor: "pointer", color: Colors.textSecondary, padding: 2, display: "flex" }}>
            {copied ? <span style={{ fontSize: 11, color: Colors.green }}>Copied!</span> : <IconCopy />}
          </button>
        </div>
        <div style={{ fontSize: 12, color: connected ? Colors.green : Colors.red }}>
          {connected ? `● ${peers.length + 1} in room` : "● Reconnecting..."}
        </div>
      </div>
      <button onClick={onLeave} style={{ background: "none", border: "none", cursor: "pointer", padding: 4, color: Colors.accent }}>
        <IconShield />
      </button>
    </div>
  );
}

// ─── MessageBubble ───
function MessageBubble({ msg }) {
  if (msg.type === "system") {
    return (
      <div style={{ textAlign: "center", padding: "8px 16px" }}>
        <span style={{ background: Colors.surfaceSecondary, padding: "4px 12px", borderRadius: 10, fontSize: 12, color: Colors.textTertiary }}>
          {msg.text}
        </span>
      </div>
    );
  }

  if (msg.payment) {
    const isOutgoing = !msg.incoming;
    return (
      <div style={{ display: "flex", justifyContent: isOutgoing ? "flex-end" : "flex-start", padding: "3px 16px" }}>
        <div style={{ maxWidth: "75%" }}>
          {msg.incoming && msg.senderName && (
            <div style={{ fontSize: 11, color: Colors.accent, padding: "0 4px 2px", fontWeight: 600 }}>{msg.senderName}</div>
          )}
          <div style={{
            background: Colors.surface,
            border: "2px solid transparent",
            borderImage: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd}) 1`,
            borderRadius: 18, padding: "12px 16px", overflow: "hidden",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: Colors.textSecondary }}>{isOutgoing ? "↑ Sent" : "↓ Received"}</span>
            </div>
            <div style={{ fontSize: 22, fontWeight: 600, color: Colors.text }}>
              {msg.payment.amount} <span style={{ fontSize: 14, color: Colors.textSecondary }}>{msg.payment.currency}</span>
            </div>
            {msg.payment.memo && <div style={{ fontSize: 13, color: Colors.textSecondary, marginTop: 2 }}>{msg.payment.memo}</div>}
            <div style={{ fontSize: 11, color: Colors.green, marginTop: 4 }}>● Confirmed</div>
          </div>
        </div>
      </div>
    );
  }

  const isOutgoing = !msg.incoming;
  return (
    <div style={{ display: "flex", justifyContent: isOutgoing ? "flex-end" : "flex-start", padding: "3px 16px" }}>
      <div style={{ maxWidth: "75%" }}>
        {msg.incoming && msg.senderName && (
          <div style={{ fontSize: 11, color: Colors.accent, padding: "0 4px 2px", fontWeight: 600 }}>{msg.senderName}</div>
        )}
        <div style={{
          background: isOutgoing ? Colors.outgoing : Colors.incoming,
          borderRadius: 18, padding: "8px 14px",
          borderBottomRightRadius: isOutgoing ? 4 : 18,
          borderBottomLeftRadius: isOutgoing ? 18 : 4,
        }}>
          <div style={{ color: Colors.text, fontSize: 15, lineHeight: 1.4 }}>{msg.text}</div>
          <div style={{ fontSize: 11, color: isOutgoing ? "rgba(255,255,255,0.5)" : Colors.textTertiary, marginTop: 2, textAlign: "right" }}>{msg.time}</div>
        </div>
      </div>
    </div>
  );
}

// ─── LiveChatView ───
function LiveChatView({ socket, onLeave }) {
  const [draft, setDraft] = useState("");
  const [showPayment, setShowPayment] = useState(false);
  const scrollRef = useRef(null);
  const typingTimer = useRef(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight);
  }, [socket.messages, socket.remoteTyping]);

  const send = () => {
    if (!draft.trim()) return;
    socket.sendMessage(draft);
    setDraft("");
    socket.sendTyping(false);
  };

  const handleDraftChange = (e) => {
    setDraft(e.target.value);
    socket.sendTyping(true);
    clearTimeout(typingTimer.current);
    typingTimer.current = setTimeout(() => socket.sendTyping(false), 2000);
  };

  if (showPayment) {
    return (
      <PaymentFlow
        peerName={socket.peers[0]?.displayName || "Room"}
        onConfirm={(amount, currency, memo) => socket.sendPayment(amount, currency, memo)}
        onClose={() => setShowPayment(false)}
      />
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <RoomHeader roomId={socket.roomId} peers={socket.peers} connected={socket.connected} onLeave={onLeave} />

      {/* Messages */}
      <div ref={scrollRef} style={{ flex: 1, overflow: "auto", padding: "8px 0", display: "flex", flexDirection: "column", gap: 2 }}>
        <div style={{ textAlign: "center", padding: "8px 0 12px" }}>
          <span style={{ background: Colors.surfaceSecondary, padding: "4px 12px", borderRadius: 10, fontSize: 12, color: Colors.textTertiary }}>
            Messages are end-to-end encrypted
          </span>
        </div>
        {socket.messages.map(m => <MessageBubble key={m.id} msg={m} />)}
        {socket.remoteTyping && (
          <div style={{ padding: "3px 16px" }}>
            <div style={{ fontSize: 11, color: Colors.accent, padding: "0 4px 2px", fontWeight: 600 }}>{socket.remoteTyping}</div>
            <div style={{ background: Colors.incoming, borderRadius: 18, padding: "10px 14px", display: "inline-flex", gap: 4 }}>
              {[0, 1, 2].map(i => (
                <div key={i} style={{ width: 7, height: 7, borderRadius: "50%", background: Colors.textSecondary, animation: `bounce 1.2s ${i * 0.2}s infinite` }} />
              ))}
            </div>
          </div>
        )}
        {socket.messages.length === 0 && socket.peers.length === 0 && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1, padding: 32, gap: 12 }}>
            <div style={{ fontSize: 40, opacity: 0.3 }}>
              <IconLink />
            </div>
            <div style={{ color: Colors.textSecondary, fontSize: 15, textAlign: "center" }}>
              Waiting for someone to join...
            </div>
            <div style={{ color: Colors.textTertiary, fontSize: 13, textAlign: "center" }}>
              Share room code <span style={{ color: Colors.accent, fontWeight: 600 }}>#{socket.roomId}</span> with a friend
            </div>
          </div>
        )}
      </div>

      {/* Composer */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderTop: `1px solid ${Colors.separator}`, background: Colors.surface }}>
        <button onClick={() => setShowPayment(true)} style={{ background: "none", border: "none", cursor: "pointer", color: Colors.accent, padding: 4, display: "flex" }}>
          <IconDollar />
        </button>
        <input
          value={draft}
          onChange={handleDraftChange}
          onKeyDown={e => e.key === "Enter" && send()}
          placeholder="Message"
          style={{ flex: 1, padding: "8px 14px", borderRadius: 20, border: `1px solid ${Colors.surfaceSecondary}`, background: Colors.surfaceSecondary, color: Colors.text, fontSize: 15, outline: "none" }}
        />
        <button onClick={send} style={{
          background: draft.trim() ? Colors.accent : Colors.surfaceSecondary,
          border: "none", borderRadius: "50%", width: 34, height: 34, cursor: "pointer",
          display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", transition: "background 0.2s",
        }}>
          <IconSend />
        </button>
      </div>
    </div>
  );
}

// ─── PaymentFlow ───
function PaymentFlow({ peerName, onConfirm, onClose }) {
  const [amount, setAmount] = useState("");
  const [currency, setCurrency] = useState("MOB");
  const [memo, setMemo] = useState("");
  const [step, setStep] = useState("enter");
  const [animating, setAnimating] = useState(false);

  const keypad = ["1", "2", "3", "4", "5", "6", "7", "8", "9", ".", "0", "⌫"];
  const tap = (k) => {
    if (k === "⌫") return setAmount(prev => prev.slice(0, -1));
    if (k === "." && amount.includes(".")) return;
    if (amount.length >= 12) return;
    setAmount(prev => prev + k);
  };

  const confirm = () => {
    setAnimating(true);
    setTimeout(() => {
      setStep("success");
      setTimeout(() => {
        onConfirm(amount || "0", currency, memo);
        onClose();
      }, 1200);
    }, 800);
  };

  if (step === "success") {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", background: Colors.bg, gap: 16 }}>
        <div style={{ animation: "scaleIn 0.4s ease-out" }}><IconCheck /></div>
        <div style={{ color: Colors.text, fontSize: 18, fontWeight: 600 }}>Payment Sent</div>
        <div style={{ color: Colors.textSecondary, fontSize: 14 }}>{amount} {currency} to {peerName}</div>
      </div>
    );
  }

  if (step === "confirm") {
    return (
      <div style={{ display: "flex", flexDirection: "column", height: "100%", background: Colors.bg }}>
        <div style={{ display: "flex", alignItems: "center", padding: "12px 16px", borderBottom: `1px solid ${Colors.separator}` }}>
          <button onClick={() => setStep("enter")} style={{ background: "none", border: "none", cursor: "pointer" }}><IconBack /></button>
          <span style={{ flex: 1, textAlign: "center", color: Colors.text, fontWeight: 600, fontSize: 17 }}>Confirm Payment</span>
          <div style={{ width: 28 }} />
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, padding: 24 }}>
          <div style={{ width: 60, height: 60, borderRadius: 30, background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 600, fontSize: 20 }}>
            {peerName.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase()}
          </div>
          <div style={{ color: Colors.textSecondary, fontSize: 15 }}>Send to {peerName}</div>
          <div style={{ fontSize: 42, fontWeight: 700, color: Colors.text }}>{amount || "0"} <span style={{ fontSize: 20, color: Colors.textSecondary }}>{currency}</span></div>
          {memo && <div style={{ color: Colors.textSecondary, fontSize: 14 }}>"{memo}"</div>}
          <div style={{ background: Colors.surfaceSecondary, borderRadius: 12, padding: "10px 16px", marginTop: 8 }}>
            <div style={{ color: Colors.textSecondary, fontSize: 12, marginBottom: 4 }}>Network fee</div>
            <div style={{ color: Colors.text, fontSize: 14 }}>0.0004 MOB</div>
          </div>
        </div>
        <div style={{ padding: "16px 24px 32px" }}>
          <button onClick={confirm} style={{
            width: "100%", padding: "16px", borderRadius: 14, border: "none", cursor: "pointer",
            background: animating ? Colors.green : `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`,
            color: "#fff", fontSize: 17, fontWeight: 600, transition: "all 0.3s",
          }}>
            {animating ? "Authenticating..." : "Confirm with Face ID"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", background: Colors.bg }}>
      <div style={{ display: "flex", alignItems: "center", padding: "12px 16px", borderBottom: `1px solid ${Colors.separator}` }}>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: Colors.accent, fontSize: 16 }}>Cancel</button>
        <span style={{ flex: 1, textAlign: "center", color: Colors.text, fontWeight: 600, fontSize: 17 }}>Send Payment</span>
        <button onClick={() => amount && setStep("confirm")} style={{ background: "none", border: "none", cursor: "pointer", color: amount ? Colors.accent : Colors.textTertiary, fontSize: 16, fontWeight: 600 }}>Next</button>
      </div>
      <div style={{ padding: "24px 16px 0", display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
        <div style={{ fontSize: 48, fontWeight: 700, color: Colors.text, minHeight: 58 }}>
          {amount || <span style={{ color: Colors.textTertiary }}>0</span>}
          <span style={{ fontSize: 20, color: Colors.textSecondary, marginLeft: 8 }}>{currency}</span>
        </div>
        <div style={{ display: "flex", gap: 0, background: Colors.surfaceSecondary, borderRadius: 8, overflow: "hidden" }}>
          {["MOB", "USD"].map(c => (
            <button key={c} onClick={() => setCurrency(c)} style={{
              padding: "6px 20px", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 600,
              background: currency === c ? Colors.accent : "transparent",
              color: currency === c ? "#fff" : Colors.textSecondary, transition: "all 0.2s",
            }}>{c}</button>
          ))}
        </div>
        <input
          value={memo}
          onChange={e => setMemo(e.target.value)}
          placeholder="Add memo (optional)"
          maxLength={256}
          style={{ width: "80%", textAlign: "center", padding: "8px 12px", borderRadius: 10, border: `1px solid ${Colors.surfaceSecondary}`, background: "transparent", color: Colors.text, fontSize: 14, outline: "none" }}
        />
      </div>
      <div style={{ flex: 1 }} />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 1, padding: "0 24px 24px" }}>
        {keypad.map(k => (
          <button key={k} onClick={() => tap(k)} style={{
            padding: "16px 0", fontSize: 24, fontWeight: 400, color: Colors.text,
            background: "transparent", border: "none", cursor: "pointer", borderRadius: 12, transition: "background 0.15s",
          }}
          onMouseDown={e => e.currentTarget.style.background = Colors.surfaceSecondary}
          onMouseUp={e => e.currentTarget.style.background = "transparent"}
          onMouseLeave={e => e.currentTarget.style.background = "transparent"}
          >{k}</button>
        ))}
      </div>
    </div>
  );
}

// ─── App Shell ───
export default function VeilDemo() {
  const socket = useVeilSocket();
  const [inRoom, setInRoom] = useState(false);

  const handleLeave = () => {
    socket.disconnect();
    setInRoom(false);
  };

  return (
    <div style={{
      width: "100%", maxWidth: 390, margin: "0 auto", height: "100vh",
      display: "flex", flexDirection: "column", background: Colors.bg,
      fontFamily: "-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', sans-serif",
      overflow: "hidden", borderLeft: `1px solid ${Colors.separator}`, borderRight: `1px solid ${Colors.separator}`,
    }}>
      <style>{`
        @keyframes bounce { 0%, 80%, 100% { transform: translateY(0) } 40% { transform: translateY(-5px) } }
        @keyframes scaleIn { 0% { transform: scale(0); opacity: 0 } 50% { transform: scale(1.2) } 100% { transform: scale(1); opacity: 1 } }
        * { -webkit-tap-highlight-color: transparent; box-sizing: border-box; }
        ::-webkit-scrollbar { display: none; }
        input::placeholder { color: ${Colors.textTertiary}; }
      `}</style>
      {/* Status bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 24px 4px", fontSize: 14, fontWeight: 600, color: Colors.text }}>
        <span>9:41</span>
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <svg width="16" height="12" viewBox="0 0 16 12"><rect x="0" y="8" width="3" height="4" rx="0.5" fill={Colors.text}/><rect x="4.5" y="5" width="3" height="7" rx="0.5" fill={Colors.text}/><rect x="9" y="2" width="3" height="10" rx="0.5" fill={Colors.text}/><rect x="13.5" y="0" width="2.5" height="12" rx="0.5" fill={Colors.text}/></svg>
          <svg width="24" height="12" viewBox="0 0 24 12"><rect x="0" y="0" width="22" height="12" rx="2" stroke={Colors.text} strokeWidth="1" fill="none"/><rect x="22.5" y="3.5" width="1.5" height="5" rx="0.5" fill={Colors.text}/><rect x="1.5" y="1.5" width="16" height="9" rx="1" fill={Colors.green}/></svg>
        </div>
      </div>
      <div style={{ flex: 1, overflow: "hidden" }}>
        {inRoom ? (
          <LiveChatView socket={socket} onLeave={handleLeave} />
        ) : (
          <JoinScreen onJoin={() => setInRoom(true)} socket={socket} />
        )}
      </div>
    </div>
  );
}
