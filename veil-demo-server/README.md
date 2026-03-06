# Veil Demo — WebSocket Relay Server

Lightweight relay server that connects Veil demo clients for real-time chat.

## Deploy to Render (free tier)

1. Push this folder to your GitHub repo
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your repo, set **Root Directory** to `veil-demo-server`
4. Settings:
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. Deploy — note the URL (e.g., `https://veil-demo-server.onrender.com`)

## Then update the frontend

Add the WebSocket URL as an environment variable in Vercel:

- Key: `VITE_WS_URL`
- Value: `wss://veil-demo-server.onrender.com` (use `wss://` not `ws://`)

Redeploy the frontend and you're live.

## Local development

```bash
npm install
npm start
# Server runs on http://localhost:3001
```

## Health check

GET `/health` returns JSON with room count and connection count.
