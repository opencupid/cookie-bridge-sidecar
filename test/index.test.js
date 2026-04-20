import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'

const SECRET = randomBytes(32).toString('hex')
const NEW_DOMAIN = 'new.example.org'
const ORIGIN_DOMAIN = 'origin.example.org'

process.env.BRIDGE_SECRET = SECRET
process.env.NEW_DOMAIN = NEW_DOMAIN
process.env.NODE_ENV = 'production'

const KEY = Buffer.from(SECRET, 'hex')

function decrypt(token) {
  const buf = Buffer.from(token, 'base64url')
  const iv = buf.subarray(0, 12)
  const tag = buf.subarray(buf.length - 16)
  const ct = buf.subarray(12, buf.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', KEY, iv)
  decipher.setAuthTag(tag)
  const plain = Buffer.concat([decipher.update(ct), decipher.final()])
  return JSON.parse(plain.toString('utf8'))
}

function encrypt(obj) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', KEY, iv)
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, ct, tag]).toString('base64url')
}

let app

async function buildApp() {
  const Fastify = (await import('fastify')).default
  const cookie = (await import('@fastify/cookie')).default

  const fastify = Fastify()
  fastify.register(cookie)

  const FALLBACK_DOMAIN = process.env.NEW_DOMAIN
  const FALLBACK_ORIGIN = `https://${FALLBACK_DOMAIN}`
  const TTL = 60
  const SECURE = process.env.NODE_ENV === 'production'

  fastify.get('/export/*', async (req, reply) => {
    const path = req.params['*'] || ''
    const s = req.cookies.__session
    const r = req.cookies.__refresh

    const target = req.cookies.__o || FALLBACK_DOMAIN
    const targetOrigin = `https://${target}`

    const clearOpts = { path: '/', secure: SECURE, sameSite: 'strict' }
    reply.clearCookie('__session', clearOpts)
    reply.clearCookie('__refresh', clearOpts)

    if (!s && !r) return reply.redirect(`${targetOrigin}/${path}`)

    const token = encrypt({ s, r, p: `/${path}`, exp: Date.now() + TTL * 1000 })
    return reply.redirect(`${targetOrigin}/_bridge?t=${token}`)
  })

  fastify.get('/import', async (req, reply) => {
    const { t } = req.query
    let data
    try {
      data = decrypt(t)
    } catch {
      return reply.redirect(FALLBACK_ORIGIN)
    }

    if (Date.now() > data.exp) return reply.redirect(FALLBACK_ORIGIN)

    if (data.s) {
      reply.setCookie('__session', data.s, {
        path: '/', sameSite: 'strict', secure: SECURE,
        httpOnly: false, maxAge: 60 * 60 * 24 * 30,
      })
    }
    if (data.r) {
      reply.setCookie('__refresh', data.r, {
        path: '/', sameSite: 'strict', secure: SECURE,
        httpOnly: true, maxAge: 60 * 60 * 24 * 90,
      })
    }

    return reply.redirect(data.p || '/')
  })

  await fastify.ready()
  return fastify
}

function findClearedCookie(cookies, name) {
  return cookies.find(
    c => c.name === name && (c.maxAge === 0 || (c.expires && c.expires.getTime() <= Date.now())),
  )
}

describe('cookie-bridge-sidecar', () => {
  before(async () => {
    app = await buildApp()
  })

  after(async () => {
    await app.close()
  })

  describe('GET /export/*', () => {
    it('redirects to __o target when no cookies present', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/inbox',
        cookies: { __o: ORIGIN_DOMAIN },
      })
      assert.equal(res.statusCode, 302)
      assert.equal(res.headers.location, `https://${ORIGIN_DOMAIN}/inbox`)
    })

    it('falls back to NEW_DOMAIN when __o cookie is absent', async () => {
      const res = await app.inject({ method: 'GET', url: '/export/inbox' })
      assert.equal(res.statusCode, 302)
      assert.equal(res.headers.location, `https://${NEW_DOMAIN}/inbox`)
    })

    it('redirects to __o-derived origin with encrypted token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/inbox',
        cookies: { __session: 'jwt-token-value', __o: ORIGIN_DOMAIN },
      })
      assert.equal(res.statusCode, 302)
      const location = new URL(res.headers.location)
      assert.equal(location.hostname, ORIGIN_DOMAIN)
      assert.equal(location.pathname, '/_bridge')

      const token = location.searchParams.get('t')
      assert.ok(token)
      const data = decrypt(token)
      assert.equal(data.s, 'jwt-token-value')
      assert.equal(data.p, '/inbox')
      assert.ok(data.exp > Date.now())
      assert.ok(data.exp <= Date.now() + 60_000)
    })

    it('clears __session and __refresh cookies on export', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/inbox',
        cookies: {
          __session: 'jwt-token-value',
          __refresh: 'refresh-uuid',
          __o: ORIGIN_DOMAIN,
        },
      })
      assert.equal(res.statusCode, 302)

      const clearedSession = findClearedCookie(res.cookies, '__session')
      const clearedRefresh = findClearedCookie(res.cookies, '__refresh')
      assert.ok(clearedSession, '__session should be cleared')
      assert.ok(clearedRefresh, '__refresh should be cleared')
      assert.equal(clearedSession.path, '/')
      assert.equal(clearedRefresh.path, '/')
    })

    it('clears cookies even when no session is present', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/inbox',
        cookies: { __o: ORIGIN_DOMAIN },
      })
      assert.ok(findClearedCookie(res.cookies, '__session'))
      assert.ok(findClearedCookie(res.cookies, '__refresh'))
    })

    it('does not clear the __o cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/inbox',
        cookies: { __session: 'jwt', __o: ORIGIN_DOMAIN },
      })
      assert.equal(findClearedCookie(res.cookies, '__o'), undefined)
    })

    it('encrypts both cookies into redirect token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/settings/profile',
        cookies: {
          __session: 'jwt-value',
          __refresh: 'refresh-uuid',
          __o: ORIGIN_DOMAIN,
        },
      })
      assert.equal(res.statusCode, 302)
      const location = new URL(res.headers.location)
      assert.equal(location.hostname, ORIGIN_DOMAIN)
      const data = decrypt(location.searchParams.get('t'))
      assert.equal(data.s, 'jwt-value')
      assert.equal(data.r, 'refresh-uuid')
      assert.equal(data.p, '/settings/profile')
    })

    it('encrypts refresh cookie only', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/dashboard',
        cookies: { __refresh: 'refresh-only-uuid', __o: ORIGIN_DOMAIN },
      })
      assert.equal(res.statusCode, 302)
      const location = new URL(res.headers.location)
      const data = decrypt(location.searchParams.get('t'))
      assert.equal(data.s, undefined)
      assert.equal(data.r, 'refresh-only-uuid')
    })

    it('handles root path export', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/export/',
        cookies: { __session: 'jwt', __o: ORIGIN_DOMAIN },
      })
      const location = new URL(res.headers.location)
      const data = decrypt(location.searchParams.get('t'))
      assert.equal(data.p, '/')
    })
  })

  describe('GET /import', () => {
    it('sets session cookie from valid token', async () => {
      const token = encrypt({ s: 'jwt-value', p: '/inbox', exp: Date.now() + 60_000 })
      const res = await app.inject({
        method: 'GET',
        url: `/import?t=${token}`,
      })
      assert.equal(res.statusCode, 302)
      // Success path now uses a same-origin relative redirect.
      assert.equal(res.headers.location, '/inbox')

      const cookies = res.cookies
      const sessionCookie = cookies.find(c => c.name === '__session')
      assert.ok(sessionCookie)
      assert.equal(sessionCookie.value, 'jwt-value')
      assert.equal(sessionCookie.path, '/')
      assert.equal(sessionCookie.sameSite, 'Strict')
      assert.equal(sessionCookie.secure, true)
      assert.notEqual(sessionCookie.httpOnly, true)
      assert.equal(sessionCookie.maxAge, 60 * 60 * 24 * 30)
    })

    it('sets refresh cookie from valid token', async () => {
      const token = encrypt({ r: 'refresh-uuid', p: '/', exp: Date.now() + 60_000 })
      const res = await app.inject({
        method: 'GET',
        url: `/import?t=${token}`,
      })
      const refreshCookie = res.cookies.find(c => c.name === '__refresh')
      assert.ok(refreshCookie)
      assert.equal(refreshCookie.value, 'refresh-uuid')
      assert.equal(refreshCookie.httpOnly, true)
      assert.equal(refreshCookie.maxAge, 60 * 60 * 24 * 90)
    })

    it('sets both cookies from valid token', async () => {
      const token = encrypt({
        s: 'jwt', r: 'refresh', p: '/dashboard', exp: Date.now() + 60_000,
      })
      const res = await app.inject({
        method: 'GET',
        url: `/import?t=${token}`,
      })
      assert.equal(res.statusCode, 302)
      assert.equal(res.headers.location, '/dashboard')
      assert.ok(res.cookies.find(c => c.name === '__session'))
      assert.ok(res.cookies.find(c => c.name === '__refresh'))
    })

    it('rejects expired token', async () => {
      const token = encrypt({ s: 'jwt', p: '/inbox', exp: Date.now() - 1000 })
      const res = await app.inject({
        method: 'GET',
        url: `/import?t=${token}`,
      })
      assert.equal(res.statusCode, 302)
      // Error path still uses absolute NEW_ORIGIN — there's no trusted path to
      // redirect to relatively.
      assert.equal(res.headers.location, `https://${NEW_DOMAIN}`)
      assert.equal(res.cookies.length, 0)
    })

    it('rejects tampered token', async () => {
      const token = encrypt({ s: 'jwt', p: '/', exp: Date.now() + 60_000 })
      const tampered = token.slice(0, -4) + 'XXXX'
      const res = await app.inject({
        method: 'GET',
        url: `/import?t=${tampered}`,
      })
      assert.equal(res.statusCode, 302)
      assert.equal(res.headers.location, `https://${NEW_DOMAIN}`)
      assert.equal(res.cookies.length, 0)
    })

    it('rejects completely invalid token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/import?t=not-a-valid-token',
      })
      assert.equal(res.statusCode, 302)
      assert.equal(res.headers.location, `https://${NEW_DOMAIN}`)
    })

    it('redirects to relative root when path is missing', async () => {
      const token = encrypt({ s: 'jwt', exp: Date.now() + 60_000 })
      const res = await app.inject({
        method: 'GET',
        url: `/import?t=${token}`,
      })
      assert.equal(res.headers.location, '/')
    })
  })
})
