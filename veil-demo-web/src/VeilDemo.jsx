import { useState, useEffect, useRef } from "react";

// ─────────────────────────────────────────────
// VEIL — Interactive Demo
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

const sampleContacts = [
  { id: "alice", name: "Alice Nakamura", avatar: "AN", lastMsg: "The quarterly report looks great!", time: "2:34 PM", unread: 2 },
  { id: "bob", name: "Bob Chen", avatar: "BC", lastMsg: "Payment received — 2.5 MOB", time: "1:15 PM", unread: 0 },
  { id: "carol", name: "Carol Whitfield", avatar: "CW", lastMsg: "Can we meet tomorrow?", time: "Yesterday", unread: 0 },
  { id: "dave", name: "Dave Okafor", avatar: "DO", lastMsg: "Sent you 1.0 MOB", time: "Yesterday", unread: 1 },
  { id: "eve", name: "Eve Martinez", avatar: "EM", lastMsg: "Safety number verified ✓", time: "Mon", unread: 0 },
];

const sampleMessages = {
  alice: [
    { id: 1, text: "Hey! Have you seen the new protocol spec?", incoming: true, time: "2:30 PM" },
    { id: 2, text: "Yes! The PQXDH handshake is elegant. ML-KEM-1024 for post-quantum security.", incoming: false, time: "2:31 PM" },
    { id: 3, text: "Agreed. The triple ratchet composition is clean too.", incoming: true, time: "2:32 PM" },
    { id: 4, text: "The quarterly report looks great!", incoming: true, time: "2:34 PM" },
  ],
  bob: [
    { id: 1, text: "Sending you payment for the design work", incoming: false, time: "1:10 PM" },
    { id: 2, text: null, incoming: false, time: "1:10 PM", payment: { amount: "2.5", currency: "MOB", memo: "Design work", status: "complete" } },
    { id: 3, text: "Payment received — 2.5 MOB", incoming: true, time: "1:15 PM" },
    { id: 4, text: "Thanks! Quick as always.", incoming: true, time: "1:15 PM" },
  ],
  dave: [
    { id: 1, text: null, incoming: true, time: "Yesterday", payment: { amount: "1.0", currency: "MOB", memo: "Lunch", status: "complete" } },
    { id: 2, text: "Sent you 1.0 MOB", incoming: true, time: "Yesterday" },
  ],
};

const transactions = [
  { id: 1, peer: "Bob Chen", amount: -2.5, memo: "Design work", date: "Today", time: "1:10 PM" },
  { id: 2, peer: "Dave Okafor", amount: 1.0, memo: "Lunch", date: "Yesterday", time: "3:45 PM" },
  { id: 3, peer: "Alice Nakamura", amount: -0.5, memo: "Coffee", date: "Mar 2", time: "9:20 AM" },
  { id: 4, peer: "Carol Whitfield", amount: 5.0, memo: "Project payment", date: "Mar 1", time: "2:00 PM" },
  { id: 5, peer: "Eve Martinez", amount: -1.25, memo: "Supplies", date: "Feb 28", time: "11:30 AM" },
];

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
const IconMessages = ({ active }) => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill={active ? Colors.accent : "none"} stroke={active ? Colors.accent : Colors.textSecondary} strokeWidth="1.5">
    <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
  </svg>
);
const IconWallet = ({ active }) => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={active ? Colors.accent : Colors.textSecondary} strokeWidth="1.5">
    <rect x="2" y="4" width="20" height="16" rx="2" /><path d="M2 10h20" /><circle cx="17" cy="14" r="1.5" fill={active ? Colors.accent : Colors.textSecondary} />
  </svg>
);
const IconSettings = ({ active }) => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={active ? Colors.accent : Colors.textSecondary} strokeWidth="1.5">
    <circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
  </svg>
);

// ─── TabBar ───
function TabBar({ tab, setTab }) {
  const tabs = [
    { key: "messages", label: "Messages", Icon: IconMessages },
    { key: "balance", label: "Balance", Icon: IconWallet },
    { key: "settings", label: "Settings", Icon: IconSettings },
  ];
  return (
    <div style={{ display: "flex", borderTop: `1px solid ${Colors.separator}`, background: Colors.surface, padding: "6px 0 env(safe-area-inset-bottom, 2px)" }}>
      {tabs.map(({ key, label, Icon }) => (
        <button key={key} onClick={() => setTab(key)} style={{ flex: 1, background: "none", border: "none", padding: "6px 0", cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
          <Icon active={tab === key} />
          <span style={{ fontSize: 10, color: tab === key ? Colors.accent : Colors.textSecondary }}>{label}</span>
        </button>
      ))}
    </div>
  );
}

// ─── ConversationList ───
function ConversationList({ onSelect }) {
  const [search, setSearch] = useState("");
  const filtered = sampleContacts.filter(c => c.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ padding: "12px 16px 4px", fontSize: 28, fontWeight: 700, color: Colors.text }}>Messages</div>
      <div style={{ padding: "4px 16px 8px" }}>
        <input
          placeholder="Search"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ width: "100%", padding: "8px 12px", borderRadius: 10, border: "none", background: Colors.surfaceSecondary, color: Colors.text, fontSize: 15, outline: "none", boxSizing: "border-box" }}
        />
      </div>
      <div style={{ flex: 1, overflow: "auto" }}>
        {filtered.map(c => (
          <button key={c.id} onClick={() => onSelect(c)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", width: "100%", background: "none", border: "none", borderBottom: `1px solid ${Colors.separator}`, cursor: "pointer", textAlign: "left" }}>
            <div style={{ width: 48, height: 48, borderRadius: 24, background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 600, fontSize: 15, flexShrink: 0 }}>
              {c.avatar}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                <span style={{ color: Colors.text, fontWeight: 600, fontSize: 16 }}>{c.name}</span>
                <span style={{ color: Colors.textTertiary, fontSize: 13, flexShrink: 0 }}>{c.time}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 2 }}>
                <span style={{ color: Colors.textSecondary, fontSize: 14, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.lastMsg}</span>
                {c.unread > 0 && (
                  <span style={{ background: Colors.accent, color: "#fff", borderRadius: 10, padding: "1px 7px", fontSize: 12, fontWeight: 600, marginLeft: 8, flexShrink: 0 }}>{c.unread}</span>
                )}
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── MessageBubble ───
function MessageBubble({ msg }) {
  if (msg.payment) {
    const isOutgoing = !msg.incoming;
    return (
      <div style={{ display: "flex", justifyContent: isOutgoing ? "flex-end" : "flex-start", padding: "3px 16px" }}>
        <div style={{
          background: Colors.surface,
          border: "2px solid transparent",
          borderImage: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd}) 1`,
          borderRadius: 18,
          padding: "12px 16px",
          maxWidth: "75%",
          overflow: "hidden",
        }}>
          <div style={{
            background: Colors.surface,
            borderRadius: 14,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: Colors.textSecondary }}>{isOutgoing ? "↑ Sent" : "↓ Received"}</span>
            </div>
            <div style={{ fontSize: 22, fontWeight: 600, color: Colors.text }}>{msg.payment.amount} <span style={{ fontSize: 14, color: Colors.textSecondary }}>{msg.payment.currency}</span></div>
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
      <div style={{
        background: isOutgoing ? Colors.outgoing : Colors.incoming,
        borderRadius: 18,
        padding: "8px 14px",
        maxWidth: "75%",
        borderBottomRightRadius: isOutgoing ? 4 : 18,
        borderBottomLeftRadius: isOutgoing ? 18 : 4,
      }}>
        <div style={{ color: Colors.text, fontSize: 15, lineHeight: 1.4 }}>{msg.text}</div>
        <div style={{ fontSize: 11, color: isOutgoing ? "rgba(255,255,255,0.5)" : Colors.textTertiary, marginTop: 2, textAlign: "right" }}>{msg.time}</div>
      </div>
    </div>
  );
}

// ─── ChatView ───
function ChatView({ contact, onBack, onPayment, onSafety }) {
  const [msgs, setMsgs] = useState(sampleMessages[contact.id] || []);
  const [draft, setDraft] = useState("");
  const [typing, setTyping] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight);
  }, [msgs]);

  const send = () => {
    if (!draft.trim()) return;
    const newMsg = { id: Date.now(), text: draft, incoming: false, time: new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) };
    setMsgs(prev => [...prev, newMsg]);
    setDraft("");
    setTyping(true);
    setTimeout(() => {
      setTyping(false);
      setMsgs(prev => [...prev, { id: Date.now() + 1, text: "Message received. End-to-end encrypted with PQXDH + Triple Ratchet.", incoming: true, time: new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) }]);
    }, 1500);
  };

  const addPaymentMsg = (amount, currency, memo) => {
    const payMsg = { id: Date.now(), text: null, incoming: false, time: new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }), payment: { amount, currency, memo, status: "complete" } };
    setMsgs(prev => [...prev, payMsg]);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", padding: "10px 12px", borderBottom: `1px solid ${Colors.separator}`, background: Colors.surface, gap: 8 }}>
        <button onClick={onBack} style={{ background: "none", border: "none", cursor: "pointer", padding: 4, display: "flex", alignItems: "center" }}><IconBack /></button>
        <div style={{ width: 36, height: 36, borderRadius: 18, background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 600, fontSize: 13 }}>{contact.avatar}</div>
        <div style={{ flex: 1 }}>
          <div style={{ color: Colors.text, fontWeight: 600, fontSize: 16 }}>{contact.name}</div>
          <div style={{ color: Colors.green, fontSize: 12 }}>● Online</div>
        </div>
        <button onClick={onSafety} style={{ background: "none", border: "none", cursor: "pointer", padding: 4, color: Colors.accent }}><IconShield /></button>
      </div>
      {/* Messages */}
      <div ref={scrollRef} style={{ flex: 1, overflow: "auto", padding: "8px 0", display: "flex", flexDirection: "column", gap: 2 }}>
        <div style={{ textAlign: "center", padding: "8px 0 12px" }}>
          <span style={{ background: Colors.surfaceSecondary, padding: "4px 12px", borderRadius: 10, fontSize: 12, color: Colors.textTertiary }}>
            Messages are end-to-end encrypted
          </span>
        </div>
        {msgs.map(m => <MessageBubble key={m.id} msg={m} />)}
        {typing && (
          <div style={{ padding: "3px 16px" }}>
            <div style={{ background: Colors.incoming, borderRadius: 18, padding: "10px 14px", display: "inline-flex", gap: 4 }}>
              {[0, 1, 2].map(i => (
                <div key={i} style={{ width: 7, height: 7, borderRadius: "50%", background: Colors.textSecondary, animation: `bounce 1.2s ${i * 0.2}s infinite` }} />
              ))}
            </div>
          </div>
        )}
      </div>
      {/* Composer */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderTop: `1px solid ${Colors.separator}`, background: Colors.surface }}>
        <button onClick={() => onPayment(addPaymentMsg)} style={{ background: "none", border: "none", cursor: "pointer", color: Colors.accent, padding: 4, display: "flex" }}><IconDollar /></button>
        <input
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => e.key === "Enter" && send()}
          placeholder="Message"
          style={{ flex: 1, padding: "8px 14px", borderRadius: 20, border: `1px solid ${Colors.surfaceSecondary}`, background: Colors.surfaceSecondary, color: Colors.text, fontSize: 15, outline: "none" }}
        />
        <button onClick={send} style={{ background: draft.trim() ? Colors.accent : Colors.surfaceSecondary, border: "none", borderRadius: "50%", width: 34, height: 34, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", transition: "background 0.2s" }}><IconSend /></button>
      </div>
    </div>
  );
}

// ─── PaymentFlow ───
function PaymentFlow({ contact, onConfirm, onClose }) {
  const [amount, setAmount] = useState("");
  const [currency, setCurrency] = useState("MOB");
  const [memo, setMemo] = useState("");
  const [step, setStep] = useState("enter"); // enter → confirm → success
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
        <div style={{ color: Colors.textSecondary, fontSize: 14 }}>{amount} {currency} to {contact.name}</div>
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
          <div style={{ width: 60, height: 60, borderRadius: 30, background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 600, fontSize: 20 }}>{contact.avatar}</div>
          <div style={{ color: Colors.textSecondary, fontSize: 15 }}>Send to {contact.name}</div>
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
            color: "#fff", fontSize: 17, fontWeight: 600, transition: "all 0.3s"
          }}>
            {animating ? "Authenticating..." : "Confirm with Face ID"}
          </button>
        </div>
      </div>
    );
  }

  // Enter amount
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
              color: currency === c ? "#fff" : Colors.textSecondary,
              transition: "all 0.2s"
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
            background: "transparent", border: "none", cursor: "pointer", borderRadius: 12,
            transition: "background 0.15s",
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

// ─── SafetyNumber ───
function SafetyNumber({ contact, onClose }) {
  const digits = Array.from({ length: 60 }, (_, i) => ((i * 7 + 3) % 10).toString()).join("");
  const groups = [];
  for (let i = 0; i < 60; i += 5) groups.push(digits.slice(i, i + 5));

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", background: Colors.bg }}>
      <div style={{ display: "flex", alignItems: "center", padding: "12px 16px", borderBottom: `1px solid ${Colors.separator}` }}>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer" }}><IconBack /></button>
        <span style={{ flex: 1, textAlign: "center", color: Colors.text, fontWeight: 600, fontSize: 17 }}>Safety Number</span>
        <div style={{ width: 28 }} />
      </div>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 20, padding: 24 }}>
        <div style={{ width: 60, height: 60, borderRadius: 30, background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 600, fontSize: 20 }}>{contact.avatar}</div>
        <div style={{ color: Colors.text, fontWeight: 600, fontSize: 18 }}>{contact.name}</div>
        <div style={{ color: Colors.textSecondary, fontSize: 13, textAlign: "center", maxWidth: 280 }}>
          Compare these numbers with {contact.name.split(" ")[0]} to verify end-to-end encryption.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "8px 16px", fontFamily: "monospace", fontSize: 18, fontWeight: 600, color: Colors.text, background: Colors.surfaceSecondary, padding: "20px 24px", borderRadius: 16 }}>
          {groups.map((g, i) => <span key={i}>{g}</span>)}
        </div>
        <div style={{ width: 120, height: 120, background: Colors.surface, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", border: `1px solid ${Colors.separator}` }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 6px)", gap: 2 }}>
            {Array.from({ length: 49 }, (_, i) => (
              <div key={i} style={{ width: 6, height: 6, background: Math.random() > 0.4 ? Colors.text : "transparent" }} />
            ))}
          </div>
        </div>
        <div style={{ fontSize: 12, color: Colors.textTertiary }}>QR Code — Scan to verify</div>
      </div>
    </div>
  );
}

// ─── BalanceView ───
function BalanceView() {
  const balance = 12.75;
  const usdEquiv = (balance * 0.24).toFixed(2);
  const grouped = {};
  transactions.forEach(t => { if (!grouped[t.date]) grouped[t.date] = []; grouped[t.date].push(t); });

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ padding: "12px 16px 4px", fontSize: 28, fontWeight: 700, color: Colors.text }}>Balance</div>
      <div style={{ padding: "20px 16px", textAlign: "center" }}>
        <div style={{ fontSize: 42, fontWeight: 700, color: Colors.text }}>{balance.toFixed(2)} <span style={{ fontSize: 18, color: Colors.textSecondary }}>MOB</span></div>
        <div style={{ fontSize: 16, color: Colors.textSecondary, marginTop: 4 }}>≈ ${usdEquiv} USD</div>
      </div>
      <div style={{ flex: 1, overflow: "auto" }}>
        {Object.entries(grouped).map(([date, txs]) => (
          <div key={date}>
            <div style={{ padding: "12px 16px 4px", fontSize: 13, fontWeight: 600, color: Colors.textTertiary, textTransform: "uppercase" }}>{date}</div>
            {txs.map(tx => (
              <div key={tx.id} style={{ display: "flex", alignItems: "center", padding: "12px 16px", borderBottom: `1px solid ${Colors.separator}`, gap: 12 }}>
                <div style={{ width: 36, height: 36, borderRadius: 18, background: tx.amount > 0 ? "rgba(48,209,88,0.15)" : "rgba(255,69,58,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <span style={{ fontSize: 16 }}>{tx.amount > 0 ? "↓" : "↑"}</span>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ color: Colors.text, fontSize: 15, fontWeight: 500 }}>{tx.peer}</div>
                  <div style={{ color: Colors.textSecondary, fontSize: 13 }}>{tx.memo}</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ color: tx.amount > 0 ? Colors.green : Colors.text, fontSize: 15, fontWeight: 600 }}>{tx.amount > 0 ? "+" : ""}{tx.amount.toFixed(2)} MOB</div>
                  <div style={{ color: Colors.textTertiary, fontSize: 12 }}>{tx.time}</div>
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── SettingsView ───
function SettingsView() {
  const [notifs, setNotifs] = useState(true);
  const Row = ({ label, value, toggle, onClick }) => (
    <div onClick={onClick} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 16px", borderBottom: `1px solid ${Colors.separator}`, cursor: onClick ? "pointer" : "default" }}>
      <span style={{ color: Colors.text, fontSize: 15 }}>{label}</span>
      {value && <span style={{ color: Colors.textSecondary, fontSize: 15 }}>{value}</span>}
      {toggle !== undefined && (
        <div onClick={e => { e.stopPropagation(); setNotifs(!notifs); }} style={{ width: 48, height: 28, borderRadius: 14, background: toggle ? Colors.green : Colors.surfaceSecondary, position: "relative", cursor: "pointer", transition: "background 0.2s" }}>
          <div style={{ width: 24, height: 24, borderRadius: 12, background: "#fff", position: "absolute", top: 2, left: toggle ? 22 : 2, transition: "left 0.2s", boxShadow: "0 1px 3px rgba(0,0,0,0.3)" }} />
        </div>
      )}
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ padding: "12px 16px 4px", fontSize: 28, fontWeight: 700, color: Colors.text }}>Settings</div>
      <div style={{ flex: 1, overflow: "auto" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "20px 16px", gap: 8 }}>
          <div style={{ width: 72, height: 72, borderRadius: 36, background: `linear-gradient(135deg, ${Colors.paymentGradientStart}, ${Colors.paymentGradientEnd})`, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 700, fontSize: 24 }}>JZ</div>
          <div style={{ color: Colors.text, fontWeight: 600, fontSize: 18 }}>Joshua</div>
          <div style={{ color: Colors.textSecondary, fontSize: 13, fontFamily: "monospace" }}>ID: a7f3b9c2</div>
        </div>
        <div style={{ padding: "8px 16px 4px", fontSize: 13, fontWeight: 600, color: Colors.textTertiary, textTransform: "uppercase" }}>Privacy</div>
        <Row label="Notifications" toggle={notifs} />
        <Row label="Message Previews" value="Never" />
        <div style={{ padding: "16px 16px 4px", fontSize: 13, fontWeight: 600, color: Colors.textTertiary, textTransform: "uppercase" }}>Security</div>
        <Row label="Encryption Protocol" value="PQXDH + SPQR" />
        <Row label="Post-Quantum KEM" value="ML-KEM-1024" />
        <Row label="Signature Algorithm" value="ML-DSA-65" />
        <div style={{ padding: "16px 16px 4px", fontSize: 13, fontWeight: 600, color: Colors.textTertiary, textTransform: "uppercase" }}>About</div>
        <Row label="Version" value="1.0.0 (preview)" />
        <Row label="Protocol Version" value="Veil v1.0" />
        <div style={{ padding: "24px 16px", textAlign: "center" }}>
          <span style={{ fontSize: 12, color: Colors.textTertiary }}>Veil — Post-Quantum Encrypted Chat & Payments</span>
        </div>
      </div>
    </div>
  );
}

// ─── App Shell ───
export default function VeilDemo() {
  const [tab, setTab] = useState("messages");
  const [activeContact, setActiveContact] = useState(null);
  const [showPayment, setShowPayment] = useState(false);
  const [showSafety, setShowSafety] = useState(false);
  const [paymentCallback, setPaymentCallback] = useState(null);

  const openPayment = (callback) => {
    setPaymentCallback(() => callback);
    setShowPayment(true);
  };

  const renderContent = () => {
    if (showSafety && activeContact) {
      return <SafetyNumber contact={activeContact} onClose={() => setShowSafety(false)} />;
    }
    if (showPayment && activeContact) {
      return (
        <PaymentFlow
          contact={activeContact}
          onConfirm={(amt, cur, memo) => paymentCallback?.(amt, cur, memo)}
          onClose={() => setShowPayment(false)}
        />
      );
    }
    if (activeContact) {
      return (
        <ChatView
          contact={activeContact}
          onBack={() => setActiveContact(null)}
          onPayment={openPayment}
          onSafety={() => setShowSafety(true)}
        />
      );
    }

    switch (tab) {
      case "messages": return <ConversationList onSelect={setActiveContact} />;
      case "balance": return <BalanceView />;
      case "settings": return <SettingsView />;
      default: return null;
    }
  };

  return (
    <div style={{ width: "100%", maxWidth: 390, margin: "0 auto", height: "100vh", display: "flex", flexDirection: "column", background: Colors.bg, fontFamily: "-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', sans-serif", overflow: "hidden", borderLeft: `1px solid ${Colors.separator}`, borderRight: `1px solid ${Colors.separator}` }}>
      <style>{`
        @keyframes bounce { 0%, 80%, 100% { transform: translateY(0) } 40% { transform: translateY(-5px) } }
        @keyframes scaleIn { 0% { transform: scale(0); opacity: 0 } 50% { transform: scale(1.2) } 100% { transform: scale(1); opacity: 1 } }
        * { -webkit-tap-highlight-color: transparent; box-sizing: border-box; }
        ::-webkit-scrollbar { display: none; }
        input::placeholder { color: ${Colors.textTertiary}; }
      `}</style>
      {/* Status bar mock */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 24px 4px", fontSize: 14, fontWeight: 600, color: Colors.text }}>
        <span>9:41</span>
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <svg width="16" height="12" viewBox="0 0 16 12"><rect x="0" y="8" width="3" height="4" rx="0.5" fill={Colors.text}/><rect x="4.5" y="5" width="3" height="7" rx="0.5" fill={Colors.text}/><rect x="9" y="2" width="3" height="10" rx="0.5" fill={Colors.text}/><rect x="13.5" y="0" width="2.5" height="12" rx="0.5" fill={Colors.text}/></svg>
          <svg width="24" height="12" viewBox="0 0 24 12"><rect x="0" y="0" width="22" height="12" rx="2" stroke={Colors.text} strokeWidth="1" fill="none"/><rect x="22.5" y="3.5" width="1.5" height="5" rx="0.5" fill={Colors.text}/><rect x="1.5" y="1.5" width="16" height="9" rx="1" fill={Colors.green}/></svg>
        </div>
      </div>
      <div style={{ flex: 1, overflow: "hidden" }}>{renderContent()}</div>
      {!activeContact && !showPayment && !showSafety && <TabBar tab={tab} setTab={setTab} />}
    </div>
  );
}
