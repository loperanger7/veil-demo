# Veil Demo (Web)

Interactive web demo for **Veil** — Post-Quantum Encrypted Chat & Payments.

**Live:** [veil-demo.vercel.app](https://veil-demo.vercel.app)

## Run locally

```bash
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

## Build

```bash
npm run build
```

Output is in `dist/`. Preview the production build with:

```bash
npm run preview
```

## Deploy to Vercel

**Option A — GitHub**

1. Push this repo (including the `veil-demo-web` folder) to GitHub.
2. In [Vercel](https://vercel.com): New Project → Import your repo.
3. Set **Root Directory** to `veil-demo-web`.
4. Build Command: `npm run build` (default). Output: `dist` (Vite default).
5. Deploy. You’ll get a URL like `veil-demo-*.vercel.app`.

**Option B — Vercel CLI**

From this directory:

```bash
npx vercel
```

Follow the prompts. For production:

```bash
npx vercel --prod
```
