# Cookie Bridge Sidecar

Stateless sidecar service that bridges authentication cookies between brand-domains where no shared parent domain exists. The target brand is carried by a client-side `__o` cookie set by the backend, so the same sidecar instance supports migration in either direction.

## How It Works

1. The frontend SPA notices (via inline script reading `__o`) that the user is on a host other than their home brand, and navigates to `/_migrate?to=<original-path>`.
2. Traefik routes `/_migrate` to the sidecar's `/export/*`.
3. The sidecar reads `__session` and `__refresh` cookies, encrypts them into an AES-256-GCM token with a 60-second TTL.
4. Source-host `__session` and `__refresh` cookies are cleared so the user no longer appears signed in on the source host.
5. Redirects to `https://<__o>/_bridge?t=<token>` — the destination host is the value of the `__o` cookie (required).
6. Traefik on the target host routes `/_bridge` to `/import`, which decrypts the token, sets cookies on the target host, and redirects to the original path (same-origin, relative).

### The `__o` cookie (required)

The backend stamps a long-lived `__o` cookie whose value is the user's home-brand domain whenever it detects that the request is served from a host other than the user's registered origin. The sidecar reads this cookie on `/export/*` to know which brand to send the user to. `__o` is persistent by design — the sidecar does **not** clear it.

If `__o` is absent, `/export/*` returns `400 Bad Request`. There is no default or fallback target domain.

### Destination path

The destination path on the target host comes from the `?to=` query param, which must be a safe local path (starts with `/`, does not start with `//`). Unsafe values are ignored and the wildcard path segment (`/export/<path>`) is used instead. Root (`/`) is used if neither yields a safe path.

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

The sidecar expects to be fronted by Traefik on each participating brand host. A typical bidirectional setup routes `Path(/_migrate)` → `/export/...` (via `addprefix`) and `Path(/_bridge)` → `/import` (via `replacepath`) on both hosts.

## Security

- **AES-256-GCM** encryption prevents cookie values from being visible in URLs or logs
- **60-second TTL** limits the token replay window
- **HTTPS-only** transport via Traefik TLS termination
- **Source-host session cookies cleared** on export so the user is signed out of the originating brand after the bridge
- **Safe-path validation** on both the export `?to=` param and the imported path, rejecting protocol-relative and absolute URLs
- **Stateless** design requires no shared storage; horizontally scalable
