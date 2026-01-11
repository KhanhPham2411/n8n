# Starting n8n Development Server

## Prerequisites

Before starting the development server, ensure all dependencies are properly installed:

### 1. Check Node.js Version
```bash
node --version
# Required: v22.14.0 or compatible with >=20.19 <= 24.x
```

### 2. Verify pnpm Installation
```bash
pnpm --version
# Required: 10.22.0 or later
```

### 3. Install All Dependencies
```bash
cd /path/to/n8n-atom
pnpm install
```

**CRITICAL:** The CLI package requires `nodemon` as a dev dependency. Verify it's installed:
```bash
cd packages/cli
pnpm list nodemon
# Should show: nodemon 3.0.1 (or later)
```

If nodemon is missing:
```bash
cd packages/cli
pnpm add -D nodemon
```

### 4. Fix Port Mismatch (IMPORTANT)

The backend runs on port **5888** but the frontend is configured to connect to port **5678**. You need to either:

**Option A: Change Backend Port to 5678 (Recommended)**
```bash
export N8N_PORT=5678
# Add to your ~/.zshrc or ~/.bashrc for persistence
```

**Option B: Change Frontend API URL to 5888**
Edit `packages/frontend/editor-ui/package.json`:
```json
"serve": "cross-env VUE_APP_URL_BASE_API=http://localhost:5888/ vite --host 0.0.0.0 --port 8080 dev",
```

### 5. Build Required Packages
```bash
# From root directory
pnpm build
```

## Starting the Development Server

### Method 1: Automated Script with Local Admin Mode (Easiest)

Use the provided script that handles all prerequisites automatically:

```bash
./scripts/dev-local-admin.sh
```

This script:
- ✅ Checks all prerequisites automatically
- ✅ Ensures nodemon is installed
- ✅ Sets correct ports (5888 for backend, 8080 for frontend)
- ✅ Automatically updates frontend to use port 5888
- ✅ Enables `N8N_LOCAL=true` (all enterprise features unlocked)
- ✅ Monitors startup and displays status
- ✅ Shows access URLs when ready
- ✅ Provides detailed logs

See [scripts/README-dev-local-admin.md](scripts/README-dev-local-admin.md) for details.

### Method 2: Full Stack (Manual)

Start both backend and frontend from the root directory:

```bash
# Set environment variables
export N8N_PORT=5888
export N8N_LOCAL=true  # Optional: enables all enterprise features

# Start dev server
pnpm run dev
```

This command:
- Runs turbo to build all packages in parallel
- Starts backend on port 5888
- Starts frontend on port 8080
- Watches for file changes

**Wait for these messages:**
```
n8n:dev: n8n ready on ::, port 5888
n8n:dev: Editor is now accessible via:
n8n:dev: http://localhost:5888
```

```
n8n-editor-ui:dev: ➜  Local:   http://localhost:8080/
```

### Method 2: Separate Backend and Frontend

If `pnpm run dev` hangs or you want more control:

#### Start Backend:
```bash
# Terminal 1: Backend
cd packages/cli
pnpm run dev

# Wait for: "n8n ready on ::, port 5888"
```

#### Start Frontend:
```bash
# Terminal 2: Frontend
cd packages/frontend/editor-ui
pnpm run dev

# Wait for: "➜  Local:   http://localhost:8080/"
```

### Method 3: Backend Only (For API Development)

```bash
cd packages/cli
pnpm run dev
```

## Verify Everything is Running

### Check Backend Health
```bash
curl http://localhost:5888/healthz
# Expected: {"status":"ok"}
```

### Check Ports
```bash678 or 5888 | Direct API access (see port note below) |
| **Health Check** | http://localhost:5678/healthz or 5888 | Server health status |
| **API Settings** | http://localhost:5678/rest/settings or 5888 | REST API settings endpoint |

> **⚠️ PORT MISMATCH WARNING:**
> - Backend default port is `5888` (configured in `@n8n/config`)
> - Frontend expects backend at `http://localhost:5678/` (configured in editor-ui package.json)
> - **You must set `export N8N_PORT=5678` before starting** OR modify frontend config
> - Standard n8n production port is `5678`
# Should show running dev processes
```

## Access Points

| Service | URL | Description |
|---------|-----|-------------|
| **Full Application** | http://localhost:8080 | Frontend connected to backend |
| **Backend API** | http://localhost:5888 | Direct API access |
| **Health Check** | http://localhost:5888/healthz | Server health status |
| **API Settings** | http://localhost:5888/rest/settings | REST API settings endpoint |

> **Important:**
> - Frontend (port 8080) proxies API calls to backend (port 5888)
> - Default port is `5888` (not the standard n8n port `5678`)
> - Frontend expects backend at `http://localhost:5678/` but you need to check [packages/frontend/editor-ui/package.json](packages/frontend/editor-ui/package.json) serve script

## Alternative Commands

### Backend Only
```bash
pnpm dev:be
```

### Frontend Only
```bash
pnpm dev:fe
```

### AI-specific Development
```bash
pnpm dev:ai
```

## Troubleshooting

### Issue: `pnpm run dev` Hangs or Stuck

**Cause:** Usually missing `nodemon` in CLI package or port conflicts.

**Solution:**
1. Kill all dev processes:
   ```bash
   pkill -9 -f "pnpm"
   pkill -9 -f "turbo"
   ```

2. Verify nodemon is installed:
   ```bash
   cd packages/cli
   pnpm list nodemon
   # If missing: pnpm add -D nodemon
   ```

3. Restart dev server

### Issue: Port Already in Use

**For Backend (5888):**
```bash
lsof -i :5888
kill -9 <PID>
```

**For Frontend (8080):**
```bash
lsof -i :8080
kill -9 <PID>
```

**Kill all n8n processes:**
```bash
pkill -9 -f "n8n"
lsof -ti :5888 | xargs kill -9 2>/dev/null
lsof -ti :8080 | xargs kill -9 2>/dev/null
```

### Issue: Backend Starts but Frontend Doesn't

Check the turbo dev output. If frontend isn't listed:

```bash
# Start frontend manually
cd packages/frontend/editor-ui
pnpm run dev
```

### Issue: "Command not found: nodemon"

```bash
cd packages/cli
pnpm add -D nodemon
# Then restart dev server
```

### Issue: Database Migration Errors

Look for migration messages in the backend logs. They should all show "Finished migration...". If any fail, the database might be corrupted.

### Issue: Playwright Tests Running (Slow)

The dev command excludes playwright by default with `--filter=!n8n-playwright`. If tests still run, verify the filter in [package.json](package.json).

## Development Workflow

1. **First Time Setup:**
   # Install dependencies
   pnpm install

   # Ensure nodemon is installed
   cd packages/cli && pnpm add -D nodemon && cd ../..

   # Build all packages
   pnpm build

   # Set backend port to match frontend expectation
   export N8N_PORT=5678
   echo 'export N8N_PORT=5678' >> ~/.zshrc  # For persistence

   # Start dev server
   pnpm run dev
   ```

2. **Daily Development:**
   ```bash
   # Ensure port is set (if not in shell config)
   export N8N_PORT=5678

   # Start dev server
   pnpm run dev

   # Wait for both services to678
[Node] Editor is now accessible via:
[Node] http://localhost:5678
```
(Or port 5888 if you didn't set N8N_PORT)

✅ Frontend logs show:
```
ROLLDOWN-VITE v7.1.16  ready in XXXms
➜  Local:   http://localhost:8080/
➜  Network: http://192.168.x.x:8080/
```

✅ Health check passes:
```bash
curl http://localhost:5678/healthz
{"status":"ok"}
```

✅ Both services accessible in browser without errors

✅ No console errors in browser developer tools about failed API calls

## Quick Checklist

Before reporting issues, verify:

- [ ] `nodemon` is installed in `packages/cli` (`pnpm list nodemon`)
- [ ] Backend port matches frontend expectation (5678) via `N8N_PORT=5678`
- [ ] Both ports 5678 and 8080 are free (`lsof -i :5678 -i :8080`)
- [ ] All dependencies installed (`pnpm install`)
- [ ] Packages built (`pnpm build`)
- [ ] Node version compatible (>=20.19 <= 24.x)
- [ ] Health check returns `{"status":"ok"}`

---

## Tested & Verified Workflow

This workflow has been verified to work correctly:

```bash
# 1. Install dependencies (first time only)
pnpm install

# 2. Ensure nodemon is installed
cd packages/cli
pnpm list nodemon  # Should show nodemon@3.0.1 or later
# If missing: pnpm add -D nodemon
cd ../..

# 3. Set the correct port
export N8N_PORT=5678

# 4. Start the dev server
pnpm run dev

# 5. Wait for startup messages (takes 20-30 seconds):
#    - "n8n ready on ::, port 5678"
#    - "Editor is now accessible via: http://localhost:5678"
#    - "ROLLDOWN-VITE v7.1.16  ready"
#    - "Local: http://localhost:8080/"

# 6. Verify in another terminal:
curl http://localhost:5678/healthz
# Expected: {"status":"ok"}

lsof -i :5678 -i :8080 | grep LISTEN
# Expected: Two node processes listening

# 7. Open browser:
open http://localhost:8080
```

**What You'll See:**
- Terminal shows compilation progress for all packages
- Backend compiles TypeScript and starts nodemon
- Frontend starts Vite dev server
- No errors about failed API connections
- Browser loads the n8n editor UI successfully
[Node] Editor is now accessible via:
[Node] http://localhost:5888
```

✅ Frontend logs show:
```
ROLLDOWN-VITE v7.1.16  ready in XXXms
➜  Local:   http://localhost:8080/
➜  Network: http://192.168.x.x:8080/
```

✅ Health check passes:
```bash
curl http://localhost:5888/healthz
{"status":"ok"}
```

✅ Both services accessible in browser without errors
