# Deploying WebSec Scanner to the internet (Windows, no command line needed)

This gets your scanner running at a public URL (like
`https://websec-scanner-xxxx.onrender.com`) that you and anyone you add as a
user can log into from any device. It stays private — only people with a
login you created can use it.

Two tools, both free: **GitHub Desktop** (to upload the code) and
**Render** (to host and run it).

---

## Part 1 — Put the code on GitHub

1. **Install GitHub Desktop**: go to https://desktop.github.com, download
   and install it, then sign in with your GitHub account.

2. **Unzip the project** you downloaded (`websec-scanner.zip`) somewhere
   you'll remember, e.g. `C:\Users\YourName\Documents\websec-scanner`.

3. In GitHub Desktop: **File → Add Local Repository**, browse to and select
   that unzipped `websec-scanner` folder, click **Add Repository**.

4. GitHub Desktop will say this folder isn't a git repository yet — click
   **"create a repository"** in that message. Leave the settings as they
   are and click **Create Repository**.

5. Click **Publish repository** in the top bar. Untick "Keep this code
   private" only if you're fine with the code being public (your actual
   login credentials and scan data are never in the code — they're created
   at runtime — so public is usually fine, but private is the safer
   default if you're unsure). Click **Publish Repository**.

Your code is now on GitHub. You can see it at
`https://github.com/<your-username>/websec-scanner`.

---

## Part 2 — Deploy it on Render

1. Go to https://render.com and click **Get Started**. Sign up using your
   GitHub account (this makes the next steps automatic).

2. On the Render dashboard, click **New +** → **Web Service**.

3. Click **Connect account** next to GitHub if asked, then find and select
   your `websec-scanner` repository from the list, click **Connect**.

4. Render will detect the `render.yaml` file in the project and offer to
   use it — click **Apply** (this automatically fills in the correct
   start command, Python version, and sets up a persistent disk so your
   scan history isn't lost on restarts).

   If it doesn't auto-detect, fill in manually:
   - **Name**: `websec-scanner` (or anything you like)
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn dashboard.app:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: Free

5. Before clicking Deploy, set your admin login. Scroll to
   **Environment Variables** and add:
   - `WEBSEC_ADMIN_USERNAME` → a username you'll remember (e.g. `admin`)
   - `WEBSEC_ADMIN_PASSWORD` → a strong password you'll remember

   This is the account you'll use to log in and add other users
   afterward. If you skip this, the app auto-generates a password for you
   and prints it once in the server logs — easy to miss, so it's simpler
   to just set it here.

6. Click **Create Web Service** (or **Deploy**). Render will build and
   start the app — this takes 2-5 minutes the first time. You'll see live
   logs; wait for a line like `Uvicorn running on http://0.0.0.0:xxxx`.

7. Once it's live, Render shows your public URL at the top of the page,
   something like `https://websec-scanner-xxxx.onrender.com`. Open it.

8. Log in with the `WEBSEC_ADMIN_USERNAME` / `WEBSEC_ADMIN_PASSWORD` you
   set in step 5.

That's it — it's live. Add domains you own under "Verified Domains" (same
as running it locally), and use the **Users** tab to create logins for
anyone else you want to have access.

---

## A few things worth knowing

- **Free tier sleeps when idle.** Render's free plan spins the app down
  after ~15 minutes of no traffic, and the next visit takes ~30-60 seconds
  to wake back up. Scheduled scans won't fire while it's asleep. If you
  want it always-on (needed for reliable scheduled scanning), upgrade to
  Render's cheapest paid plan (~$7/month) under the service's Settings.

- **Nuclei won't be available on Render.** Render's environment doesn't
  have it preinstalled and the free tier can't install extra system
  binaries easily. The passive checks (headers, TLS, cookies, exposed
  files, CORS) all still work fully — Nuclide is an optional extra you'd
  need a different host (e.g. a small VPS) to get, if you want it.

- **Updating the app later**: make your changes locally, then in GitHub
  Desktop click **Commit to main**, then **Push origin**. Render
  auto-detects the push and redeploys within a couple minutes — no need
  to repeat the Render setup steps.

- **Your data persists** across redeploys and restarts because of the
  persistent disk `render.yaml` sets up — domains, scan history, schedules,
  and users aren't wiped when Render restarts the app.

- **Changing the admin password later**: log in, go to the **Account** tab,
  and change it there — you don't need to touch Render's environment
  variables again after the first setup.
