# Cookie Bridge Sidecar

Stateless sidecar service that bridges authentication cookies during domain migrations where no shared parent domain exists (e.g., `old.example.org` → `new.example.org`).

## How It Works

1. User visits `old.example.org/inbox`
2. Traefik routes all old-domain traffic to `/export/*`
3. The sidecar reads `__session` and `__refresh` cookies, encrypts them into an AES-256-GCM token with a 60-second TTL
4. Redirects to `new.example.org/_bridge?t=<token>`
5. Traefik routes `/_bridge` to `/import`, which decrypts the token, sets cookies on the new domain, and redirects to the original path

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
| `NEW_DOMAIN` | `new.example.org` | Target domain for redirects |
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
- **Stateless** design requires no shared storage; horizontally scalable
