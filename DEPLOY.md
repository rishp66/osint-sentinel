# OSINT Sentinel — Azure Deploy Runbook (for Claude Code)

Goal: frontend on Azure Static Web Apps, backend on Azure Container Apps.
Domain `osintsentinel.dev`. Image registry `ghcr.io` (free). Secrets via Doppler.
Cost target ~$0/mo via scale-to-zero.

Two steps need the human — pause and ask at each:
- Phase 3: make the ghcr package public (GitHub UI).
- Phase 5: add DNS records at Porkbun.
If any `az` flag is rejected, check `<cmd> --help` and adapt.

## Vars (export once)
```
export RG=osint-sentinel-rg LOC=eastus2 ENV=osint-sentinel-env
export APP=osint-sentinel-api SWA=osint-sentinel-web
export IMAGE=ghcr.io/rishp66/osint-sentinel-backend:latest
```

## Prereqs (verify; install/login if missing)
- `az account show` succeeds (else `az login`).
- `docker version` — daemon running.
- `doppler --version`; run `doppler setup` inside `backend/` if unconfigured.
- `gh auth status` — must include `write:packages` (`gh auth refresh -s write:packages`).
- `az provider register -n Microsoft.App && az provider register -n Microsoft.OperationalInsights`

## Phase 1 — Repo cleanup
Project is wrongly nested in `osint-sentinel/`; root has stray `node_modules` + `package*.json`.
- Move `osint-sentinel/backend` and `osint-sentinel/frontend` to repo root.
- Delete root `node_modules`, `package.json`, `package-lock.json`, and the now-empty `osint-sentinel/`.
- Create `.gitignore`:
```
node_modules/
__pycache__/
*.pyc
venv/
.env
dist/
.DS_Store
```
- `git rm -r --cached node_modules` (ignore error if untracked). Commit.

## Phase 2 — Backend Dockerfile
Create `backend/Dockerfile`:
```
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000"]
```
Create `backend/.dockerignore`:
```
venv/
__pycache__/
*.pyc
.env
```
Verify locally:
```
cd backend
docker build -t osint-test .
docker run --rm -d -p 8000:8000 --env-file <(doppler secrets download --no-file --format env) --name osint-test osint-test
curl -s localhost:8000/health   # expect {"status":"ok"}
docker stop osint-test
```

## Phase 3 — Backend to Container Apps
Build + push image:
```
cd backend
docker build -t $IMAGE .
gh auth token | docker login ghcr.io -u rishp66 --password-stdin
docker push $IMAGE
```
PAUSE: ask the human to set the `osint-sentinel-backend` package to Public
(github.com/users/rishp66/packages → package → Settings → Change visibility).

Create infra:
```
az group create -n $RG -l $LOC
az containerapp env create -n $ENV -g $RG -l $LOC
```
Secrets: for each key in `backend/.env.example` that has a value in Doppler
(LIGHTNING_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY,
OTX_API_KEY, IPINFO_TOKEN, URLSCAN_API_KEY, HYBRID_ANALYSIS_API_KEY,
ABUSECH_AUTH_KEY, PULSEDIVE_API_KEY) — build two arg lists:
- secret name = key lowercased, `_`→`-` (e.g. `virustotal-api-key`)
- value = `doppler secrets get <KEY> --plain`
- env ref = `<KEY>=secretref:<secret-name>`
Skip keys that are empty/absent in Doppler.

Create the app (substitute the built `--secrets` and `--env-vars` lists):
```
az containerapp create -n $APP -g $RG --environment $ENV \
  --image $IMAGE --target-port 8000 --ingress external \
  --min-replicas 0 --max-replicas 2 --cpu 0.5 --memory 1.0Gi \
  --secrets <name=value ...> \
  --env-vars <KEY=secretref:name ...> \
    CORS_ORIGINS=https://osintsentinel.dev,https://www.osintsentinel.dev \
    TRUST_PROXY_HEADERS=true DEBUG=false
```
Capture + verify:
```
FQDN=$(az containerapp show -n $APP -g $RG --query properties.configuration.ingress.fqdn -o tsv)
curl -s https://$FQDN/health   # expect {"status":"ok"}
```

## Phase 4 — Frontend to Static Web Apps
```
az staticwebapp create -n $SWA -g $RG -l $LOC \
  --source https://github.com/rishp66/osint-sentinel --branch main \
  --app-location frontend --output-location dist --login-with-github
```
This adds `.github/workflows/azure-static-web-apps-*.yml`. Edit that file: in the
build/deploy job add an `env:` entry `VITE_API_BASE_URL: https://api.osintsentinel.dev`.
Commit + push → Action builds and deploys. Then:
```
az staticwebapp show -n $SWA -g $RG --query defaultHostname -o tsv   # = SWA_HOST
```

## Phase 5 — DNS (human adds records at Porkbun)
Register custom domains and capture validation tokens:
```
az staticwebapp hostname set -n $SWA -g $RG --hostname osintsentinel.dev --validation-method dns-txt-token
az staticwebapp hostname set -n $SWA -g $RG --hostname www.osintsentinel.dev
az containerapp hostname add -n $APP -g $RG --hostname api.osintsentinel.dev
```
PAUSE: print this table with captured values and ask the human to add the records
at Porkbun (DNS tab):

| Type  | Host       | Value                          |
|-------|------------|--------------------------------|
| ALIAS | @          | <SWA_HOST>                     |
| TXT   | @          | <SWA apex validation token>    |
| CNAME | www        | <SWA_HOST>                     |
| CNAME | api        | <FQDN>                         |
| TXT   | asuid.api  | <Container Apps validation id> |

After the human confirms records are saved, wait ~5 min, then bind the API cert:
```
az containerapp hostname bind -n $APP -g $RG --hostname api.osintsentinel.dev \
  --environment $ENV --validation-method CNAME
```
Re-run if validation is still pending. SWA issues its cert automatically once the
TXT/ALIAS records resolve.

## Phase 6 — Verify
```
curl -s https://api.osintsentinel.dev/health    # expect {"status":"ok"}
```
- Load `https://osintsentinel.dev`, run a full scan.
- Check browser console: no CORS errors. If present, confirm backend `CORS_ORIGINS`
  exactly matches the frontend origin and redeploy with `az containerapp update`.

## Notes
- Scale-to-zero → first request after idle has a ~10–30s cold start; expected.
- In-memory cache resets on cold start; harmless (optimization only).
- To update backend later: rebuild + push `$IMAGE`, then
  `az containerapp update -n $APP -g $RG --image $IMAGE`.
  