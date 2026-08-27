# SentinelTrace deployment

This setup deploys the FastAPI backend to Render and the React frontend to
Vercel. The backend must run from the repository root so it can load both the
root requirements and the trained model under `ml/artifacts`.

## 1. Deploy the backend on Render

1. In Render, choose **New > Blueprint** and connect
   `lovelybrute/SentinelTrace`.
2. Select the repository-root `render.yaml`.
3. Set `ALLOWED_ORIGINS=https://YOUR-VERCEL-DOMAIN` when Render prompts you.
4. For persistent production data, add `DATABASE_URL` in the Render dashboard
   with a managed PostgreSQL URL. A temporary demo can omit it and use SQLite;
   free-instance files can be lost during redeployment or restart.
5. Deploy and wait for the health check to pass.

The blueprint uses Python 3.12, installs `requirements.txt`, and starts:

```bash
cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT
```

Do not add a Render root directory. Doing so prevents the backend from reading
the trained model under `ml/artifacts`.

## 2. Deploy the frontend on Vercel

1. Import `lovelybrute/SentinelTrace` into Vercel.
2. Set **Root Directory** to `web`.
3. Keep the detected Vite build settings (`npm run build`, output `dist`).
4. Add:
   - `VITE_API_BASE_URL=https://YOUR-RENDER-SERVICE.onrender.com`
5. Deploy or redeploy after saving the variable.

Return to Render and ensure `ALLOWED_ORIGINS` exactly matches the final Vercel
origin, including `https://` and without a trailing slash.

## 3. Verify production

Open:

- `https://YOUR-RENDER-SERVICE.onrender.com/`
- `https://YOUR-RENDER-SERVICE.onrender.com/docs`
- `https://YOUR-RENDER-SERVICE.onrender.com/model/metrics`
- `https://YOUR-VERCEL-DOMAIN/model-performance`
- `https://YOUR-VERCEL-DOMAIN/analyzer`

Upload a non-sensitive test `.eml` and confirm the result displays
**Validated phishing probability**. Never upload private evidence to a demo.

## 4. Automatic checks

GitHub Actions runs local-only backend tests and the frontend production build.
Render deploys `main` after those checks pass. Vercel can deploy `main`
through its native Git integration, so the workflow needs no provider secrets.

If deployment fails, inspect the provider build log first. Common causes are a
missing environment variable, an incorrect frontend API URL, or an
`ALLOWED_ORIGINS` value that does not exactly match the frontend origin.
