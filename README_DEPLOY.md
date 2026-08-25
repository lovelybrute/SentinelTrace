Deployment checklist (no secrets in repo)

1) GitHub repository
   - Go to your repository Settings → Secrets and variables → Actions → New repository secret.
   - Add the following secrets:
     - VERCEL_TOKEN — your Vercel Personal Token
     - VERCEL_ORG_ID — Vercel organization id
     - VERCEL_PROJECT_ID — Vercel project id for the frontend
     - RENDER_API_KEY — Render API key (service key)
     - RENDER_SERVICE_ID — Render service id for the backend
     - DATABASE_URL — (optional) Supabase/Postgres connection string (if not using Render-managed env)

2) Vercel (Frontend)
   - Import the repository in Vercel, root directory: `web`.
   - In Project Settings → Environment Variables add `VITE_API_BASE_URL` = `https://<your-render-domain>`
   - Link the project and deploy.

3) Render (Backend)
   - Create a new Web Service and connect the repository; set the root to `backend`.
   - Build Command: `pip install -r requirements.txt` (repo root has requirements)
   - Start Command: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app`
   - In Environment, set `DATABASE_URL` to your Supabase Postgres connection and `ALLOWED_ORIGINS` to your Vercel domain.
   - Alternatively, create the service by importing `render.yaml` during setup.

4) Supabase (Database)
   - Create project and copy the DATABASE_URL (connection string).
   - Add it to Render as `DATABASE_URL` secret.

5) Automated deploys
   - Push to `main` branch. GitHub Actions `CI & Deploy` will build the frontend and trigger Vercel, then trigger a Render deploy.

Notes and troubleshooting
- Do NOT commit any `.env` or secret files. Use the GitHub Secrets UI and the cloud dashboards.
- If CORS errors occur, set `ALLOWED_ORIGINS` on the Render service to your Vercel domain (no trailing slash).
- If database migrations are needed, consider adding Alembic; currently backend uses `create_all()` on startup.

Files added to repo:
- `render.yaml` — optional Render import config
- `web/vercel.json` — Vercel build config
- `.github/workflows/deploy.yml` — GitHub Actions CI & deploy

If you want, I can now: (1) open pull request with these CI files, or (2) help you populate the GitHub secrets (instructions).