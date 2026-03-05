# Push to GitHub & Deploy on Vercel

GitHub username: **loperanger7** · Repo used below: **veil-demo**

---

## Step 1: Push to GitHub

From **Chat Build Project** (parent of `veil-demo-web`):

```bash
cd "/Users/joshuagoldbard/Chat Build Project"

git init
git add .
git commit -m "Add Veil demo web app"
```

Create the repo on GitHub: **[github.com/new](https://github.com/new)** — set the name to `veil-demo` (or leave default), then **Create repository**. Don’t add a README or .gitignore.

Then run:

```bash
git remote add origin https://github.com/loperanger7/veil-demo.git
git branch -M main
git push -u origin main
```

---

## Step 2: Deploy on Vercel

**Option A — Vercel dashboard (recommended)**

1. Go to [vercel.com](https://vercel.com) and sign in (GitHub is easiest).
2. **Add New** → **Project** → **Import** your GitHub repo.
3. **Root Directory**: click **Edit**, choose `veil-demo-web`, then **Continue**.
4. Leave Build Command as `npm run build` and Output as `dist`. Click **Deploy**.
5. Your demo will be live at a URL like `your-repo-name-xxx.vercel.app`.

**Option B — Vercel CLI**

From this folder (`veil-demo-web`):

```bash
cd "/Users/joshuagoldbard/Chat Build Project/veil-demo-web"
npx vercel
```

Log in if prompted, accept defaults. For production:

```bash
npx vercel --prod
```

You’ll get a live URL in the terminal.
