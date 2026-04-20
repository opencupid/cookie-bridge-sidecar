import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'

const app = Fastify()
app.register(cookie)

const FALLBACK_DOMAIN = process.env.NEW_DOMAIN
const FALLBACK_ORIGIN = `https://${FALLBACK_DOMAIN}`
const KEY = Buffer.from(process.env.BRIDGE_SECRET, 'hex')
const TTL = 60
const SECURE = process.env.NODE_ENV === 'production'

function encrypt(obj) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', KEY, iv)
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, ct, tag]).toString('base64url')
}

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

app.get('/export/*', async (req, reply) => {
  const path = req.params['*'] || ''
  const s = req.cookies.__session
  const r = req.cookies.__refresh

  // Origin brand comes from the __o cookie (set by the backend when the user's
  // home brand differs from the serving host). Fall back to NEW_DOMAIN for
  // deployments that haven't started setting __o yet.
  const target = req.cookies.__o || FALLBACK_DOMAIN
  const targetOrigin = `https://${target}`

  // Always clear source-host session cookies — the user is leaving this brand.
  // __o is persistent by design and must NOT be cleared.
  const clearOpts = { path: '/', secure: SECURE, sameSite: 'strict' }
  reply.clearCookie('__session', clearOpts)
  reply.clearCookie('__refresh', clearOpts)

  if (!s && !r) return reply.redirect(`${targetOrigin}/${path}`)

  const token = encrypt({ s, r, p: `/${path}`, exp: Date.now() + TTL * 1000 })
  return reply.redirect(`${targetOrigin}/_bridge?t=${token}`)
})

app.get('/import', async (req, reply) => {
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

  // Response is served on the target host, so a relative redirect keeps us
  // on the same origin without coupling the import path to NEW_DOMAIN.
  return reply.redirect(data.p || '/')
})

app.listen({ port: 3099, host: '0.0.0.0' })
