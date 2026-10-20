# XEROX Platform — Production Deployment & Rollback Guide

## Architecture Overview
- **Frontend**: Single Page Application built with React 18, Vite 5, Tailwind CSS, and Lucide React icons. Hosted statically on **GitHub Pages** (`https://xeroxxx69.github.io/xerox-cybersecurity-platform/`).
- **Backend**: FastAPI asynchronous core running with Uvicorn, SQLAlchemy 2.0 (asyncpg / aiosqlite fallback), Redis cache (fakeredis fallback), and JWT session security enclave. Deployable to **Railway**, **Render**, or any container platform.

---

## 1. Backend Deployment Procedure

### A. Deploying to Railway
1. **Repository Connection**:
   - In the [Railway Dashboard](https://railway.app/), link the GitHub repository: `xeroxxx69/xerox-cybersecurity-platform`.
2. **Build Configuration**:
   - Railway reads `railway.json` located at the root of the repository:
     - **Builder**: `DOCKERFILE`
     - **DockerfilePath**: `Dockerfile`
     - **Healthcheck Path**: `/health`
     - **Timeout**: `100s`
3. **Environment Variables**:
   Configure the following variables in Railway Service Settings:
   - `ENVIRONMENT`: `production`
   - `PORT`: `${{PORT}}` (injected automatically by Railway)
   - `SECRET_KEY`: `<generate-a-secure-random-64-character-string>`
   - `DATABASE_URL`: `${{Postgres.DATABASE_URL}}` (provision Railway PostgreSQL add-on, or default to SQLite fallback)
   - `REDIS_URL`: `${{Redis.REDIS_URL}}` (provision Railway Redis add-on, or default to in-memory fallback)
   - `CORS_ORIGINS`: `["https://xeroxxx69.github.io","http://localhost:5173"]`
   - `COOKIE_SECURE`: `true`
   - `COOKIE_SAMESITE`: `none`
4. **Custom Domain / Railway Public URL**:
   - Under Service Settings > **Networking**, click **Generate Domain** or map a custom domain.
   - Note down the generated domain (e.g., `https://web-production-xxxx.up.railway.app`).

### B. Deploying to Render (Free Web Service)
Render is a recommended free backend hosting platform for the XEROX FastAPI backend.

#### Option 1: Render Blueprint (Zero-Config 1-Click Setup)
1. Log in to [Render](https://render.com).
2. Click **New +** > **Blueprint**.
3. Connect your repository: `xeroxxx69/xerox-cybersecurity-platform`.
4. Render will detect [`render.yaml`](file:///E:/Xerox/render.yaml) and automatically configure:
   - **Service Name**: `xerox-backend`
   - **Runtime**: `Python`
   - **Root Directory**: `backend`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path**: `/health/live`
   - **Database**: Optional free PostgreSQL (`xerox-db`)
5. Click **Apply**. Render will build and deploy the container on a free `*.onrender.com` URL with automatic TLS/HTTPS.

#### Option 2: Manual Web Service Setup on Render
If deploying without a Blueprint:
1. Click **New +** > **Web Service**.
2. Connect the `xeroxxx69/xerox-cybersecurity-platform` repository.
3. Configure the service settings:
   - **Root Directory**: `backend`
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: `Free` (0.1 CPU, 512 MB RAM)
   - **Health Check Path**: `/health/live`
4. Add Environment Variables:
   - `ENVIRONMENT` = `production`
   - `SECRET_KEY` = `<random-32-char-string>`
   - `CORS_ORIGINS` = `["https://xeroxxx69.github.io"]`
   - `COOKIE_SECURE` = `true`
   - `COOKIE_SAMESITE` = `none`
   - `DATABASE_URL` = *(Optional: attach Render PostgreSQL URL or leave unset to use SQLite)*
5. Click **Create Web Service**. Note the assigned URL: `https://<your-service>.onrender.com`.

### C. Deployment Verification & Smoke Testing
Run the automated end-to-end smoke test script against the deployed backend:
```bash
node tests/integration_auth_test.mjs https://<your-backend-domain>/api/v1
```
The script validates:
- Endpoint readiness at `/health/live`, `/health/ready`, and `/api/v1/health`
- Database connectivity
- CORS preflight response for `Origin: https://xeroxxx69.github.io`
- Threat analysis endpoints (`POST /api/v1/analyze/url`)
- Analyst registration, credential verification, and session token issuance
- Isolation of authenticated history records


---

## 2. Frontend Configuration & Deployment

### A. Setting the Production API URL
The frontend uses a centralized, prioritized API configuration hierarchy:
1. **Analyst Runtime UI Override**: Configurable in the Login UI via the **Security Enclave Connection** panel (persisted in `localStorage["xerox_custom_api_url"]`).
2. **GitHub Repository Variable**:
   - Go to `Settings > Secrets and variables > Actions > Variables` in the GitHub repository.
   - Add/Update variable: `VITE_API_URL` = `https://<your-backend-domain>/api/v1`
3. **Automated Deployment**:
   - Pushing to `master` triggers `.github/workflows/deploy-pages.yml`.
   - The workflow runs automated regression unit tests, compiles the production bundle, ensures SPA 404 fallback routing, and deploys to GitHub Pages.

---

## 3. Rollback Procedure

### A. Frontend Rollback
1. **Via Git**:
   ```bash
   git revert <commit-hash>
   git push origin master
   ```
   GitHub Actions will automatically redeploy the previous working version.
2. **Immediate Runtime Fix**:
   Analysts can open `https://xeroxxx69.github.io/xerox-cybersecurity-platform/login`, click **Security Enclave Connection**, and update or reset the API Base URL directly without waiting for a redeployment.

### B. Backend Rollback
1. **Railway Deployment Rollback**:
   - In the Railway Dashboard under the service **Deployments** tab, locate the last healthy deployment.
   - Click the three dots `...` next to the deployment and select **Rollback**.
   - Railway will immediately route traffic back to the previous container image.
2. **Database Migration Downgrade (if needed)**:
   ```bash
   alembic downgrade -1
   ```
