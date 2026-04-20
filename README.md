# Cookie Bridge Sidecar

Stateless sidecar service that bridges authentication cookies during domain migrations where no shared parent domain exists (e.g., `old.example.org` → `new.example.org`).

## How It Works

1. User visits `old.example.org/inbox`
2. Traefik routes all old-domain traffic to `/export/*`
3. The sidecar reads `__session` and `__refresh` cookies, encrypts them into an AES-256-GCM token with a 60-second TTL
4. Source-host `__session` and `__refresh` cookies are cleared so the user no longer appears signed in on the old domain
5. Redirects to `<target>/_bridge?t=<token>` where `<target>` is the value of the `__o` ("origin brand") cookie if present, or `NEW_DOMAIN` as a fallback
6. Traefik routes `/_bridge` to `/import`, which decrypts the token, sets cookies on the target host, and redirects to the original path (relative, same-origin)

### The `__o` cookie

The backend stamps a long-lived `__o` cookie whose value is the user's home-brand domain (e.g. `origin.example.org`) whenever it detects that the request is served from a host other than the user's registered origin. The sidecar reads this cookie on `/export/*` to know which brand to send the user to. `__o` is persistent by design — the sidecar does **not** clear it.

If `__o` is absent (older deployments, new visitors), the sidecar falls back to `NEW_DOMAIN` from its environment, preserving the original single-target behavior.

## Setup

### Generate a bridge secret

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Configure environment

Copy `.env.example` to `.env` and fill in the values:

```sh
cp .env.example .env
```

| Variable | Example | Purpose |
|----------|---------|---------|
| `NEW_DOMAIN` | `new.example.org` | Fallback target domain when `__o` cookie is absent |
| `OLD_DOMAIN` | `old.example.org` | Source domain (used in Traefik routing) |
| `BRIDGE_SECRET` | 64-char hex | 32-byte AES-256 key |
| `NODE_ENV` | `production` | Controls cookie `Secure` flag |

### Run with Docker Compose

```sh
docker compose up -d
```

## Development

```sh
npm install
npm start
```

### Tests

```sh
npm test
```

## Traefik Integration

The `docker-compose.yml` includes Traefik labels that handle routing:

- **Old domain**: All requests to `OLD_DOMAIN` are prefixed with `/export` and forwarded to the sidecar
- **New domain**: Requests to `/_bridge` on `DOMAIN` are rewritten to `/import` and forwarded to the sidecar

The sidecar expects to run behind a Traefik reverse proxy that terminates TLS.

## Security

- **AES-256-GCM** encryption prevents cookie values from being visible in URLs or logs
- **60-second TTL** limits the token replay window
- **HTTPS-only** transport via Traefik TLS termination
- **Source-host session cookies cleared** on export so the user is signed out of the originating brand after the bridge
- **Stateless** design requires no shared storage; horizontally scalable
