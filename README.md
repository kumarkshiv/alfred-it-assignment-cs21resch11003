# Partner lab API

Partner labs send samples and read results through an HTTP API. Admins (people) register partners and can cut one off at once.

```
partner / admin ──HTTPS :8443──▶ Caddy (proxy) ──▶ app :8000 ──▶ SQLite on a Docker volume
                                   only published port    not published to the host
```

## Run it

```sh
docker compose up -d --build
curl -k https://localhost:8443/health        # {"status":"ok"}
```

`-k` is needed because the certificate comes from Caddy's own internal CA (self-signed). Only the proxy publishes a port (8443); the app and the database have none. Data lives on the `app_data` volume and survives `docker compose down` and `up` (`docker compose down -v` deletes it).

## Sample users and how to get their sign-in details

At start-up two accounts are created if they do not exist yet:

| Role | Account |
|---|---|
| admin (person) | username `admin` |
| partner lab (API client) | `Demo Lab`, scopes `samples:write results:read`, with one finished demo result |

No password is written in this repository. They are random and are written once to a private file on the data volume:

```sh
docker compose exec app cat /data/initial-credentials.txt
```

It lists the admin password and the demo partner's `client_id` and `client_secret`. To choose the admin password yourself, set `ADMIN_PASSWORD` in the environment (or a `.env` file next to `docker-compose.yml`) before the first start. Once you have saved the details, delete the file with `docker compose exec app rm /data/initial-credentials.txt`; the accounts keep working. For a real deployment set `SEED_SAMPLE_USERS=0` and register partners through the API.

## Using the API

Set `API=https://localhost:8443` and add `-k` to curl.

```sh
# 1. Admin signs in (admin tokens last 1 hour)
ADMIN=$(curl -sk $API/admin/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<from credentials file>"}' | jq -r .access_token)

# 2. Admin registers a partner: the client_secret is shown only in this response
curl -sk $API/admin/partners -H "Authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"name":"Acme Labs","scopes":["samples:write","results:read"]}'

# 3. Partner exchanges its credentials for a 15-minute access token
curl -sk $API/oauth/token -d grant_type=client_credentials \
  -d client_id=<client_id> -d client_secret=<client_secret>
#   -> {"access_token":"…","token_type":"Bearer","expires_in":900,"scope":"results:read samples:write"}
#   (HTTP Basic auth and a JSON body work too; add -d scope="results:read" to ask for fewer scopes)

# 4. Partner submits a sample, then reads results of its own samples
curl -sk $API/samples -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"sample_ref":"ACME-0001","sample_type":"blood","collected_at":"2026-11-24T08:30:00Z"}'
curl -sk $API/results -H "Authorization: Bearer $TOKEN"
curl -sk $API/results/<sample id> -H "Authorization: Bearer $TOKEN"

# 5. Admin revokes the partner: its tokens stop working on the very next request
curl -sk -X POST $API/admin/partners/<id>/revoke -H "Authorization: Bearer $ADMIN"
```

| Endpoint | Who | Notes |
|---|---|---|
| `GET /health` | anyone | no sign-in; checks the database |
| `POST /admin/login`, `POST /admin/logout` | admin | |
| `POST /admin/partners` | admin | name + scopes; returns `client_id` and one-time `client_secret` |
| `GET /admin/partners`, `GET /admin/partners/{id}` | admin | |
| `POST /admin/partners/{id}/revoke` | admin | immediate and permanent; deletes the partner's tokens |
| `POST /admin/partners/{id}/rotate-secret` | admin | new secret; old secret and tokens stop working |
| `GET /admin/samples`, `PUT /admin/samples/{id}/result` | admin | lab staff record results here (`final`, `preliminary` or `rejected`) |
| `POST /oauth/token` | partner | `client_credentials` grant |
| `POST /samples` | partner, `samples:write` | `sample_ref` is unique per partner (409 on repeat) |
| `GET /results`, `GET /results/{sample id}` | partner, `results:read` | own samples only; `state` is `pending` until a result exists |

Errors are JSON: `{"error": "<code>", "message": "…"}`. A partner asking for another partner's sample gets `404`, the same as for a sample that does not exist.

## Security decisions

- **Revocation is immediate** because access tokens are opaque and checked against the database on every request, together with the partner's revoked flag. No waiting for the 15 minutes.
- Client secrets are 256-bit random values stored as SHA-256 hashes; access tokens are stored as hashes too; admin passwords use scrypt. A database leak or backup does not reveal usable credentials. The secret is shown once, at registration or rotation.
- Five failed sign-ins or token requests for the same account from the same address lock that pair out for 5 minutes (`429` with `Retry-After`). Unknown accounts take as long to reject as known ones.
- A partner token cannot open admin endpoints, and scope is checked on each call. The scopes in a token can be narrower than the partner's allowed scopes, never wider.
- Request bodies are limited (1 MB at the proxy, 64 KB in the app). The app runs as an unprivileged user on a read-only filesystem except `/data`.
- Logs are one JSON line per request on stdout (`docker compose logs app`): time, method, path without query string, status, duration, caller id, address. No headers, bodies or secrets. Admin actions are also recorded in the `audit_events` table.

## Backup and restore

```sh
scripts/backup.sh                          # writes backups/partnerapi-<UTC time>.db (owner-only), service keeps running
scripts/restore.sh backups/partnerapi-….db # asks first; add --yes to skip the question
```

The backup uses SQLite's online backup, so it is consistent while requests are being served, and it is integrity-checked before it is written. Restore stops the app, checks the file (integrity and expected tables) before replacing anything, keeps the old database as `partnerapi.db.pre-restore` on the volume, and starts the app again. Treat backup files as sensitive: they hold sample data and credential hashes. They are not encrypted.

## Tests

```sh
./run-tests.sh            # needs Python 3.11+ with requirements-dev.txt installed
./run-tests.sh --docker   # same tests inside the application image
```

34 tests cover health, admin sign-in and lockout, partner registration, token exchange and the 15-minute expiry (with a movable clock), scope enforcement, isolation between partners, immediate revocation, secret rotation, log lines, persistence across restarts, the sample users and backup/restore.

## Known limits

- One app worker with threads (SQLite has one writer). That is plenty for this workload; moving to PostgreSQL is the step if it grows.
- The proxy's certificate is self-signed; partners must trust it or be given a real certificate (replace `tls internal` in the `Caddyfile` with a domain name for a Let's Encrypt certificate).
- Port 8443 is published on all interfaces. To limit it to the local machine, change the mapping to `"127.0.0.1:8443:8443"`.
- There is no way to un-revoke a partner; register a new one.
