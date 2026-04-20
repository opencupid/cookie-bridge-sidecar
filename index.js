import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'

const app = Fastify()
app.register(cookie)

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

// Only accept local paths. Rejects protocol-relative `//host` and absolute URLs.
function safePath(p) {
  if (typeof p !== 'string' || !p.startsWith('/') || p.startsWith('//')) return null
  return p
}

app.get('/export/*', async (req, reply) => {
  const target = req.cookies.__o
  if (!target) return reply.code(400).send('missing __o cookie')
  const targetOrigin = `https://${target}`

  const dest = safePath(req.query.to) || `/${req.params['*'] || ''}`
  const s = req.cookies.__session
  const r = req.cookies.__refresh

  const clearOpts = { path: '/', secure: SECURE, sameSite: 'strict' }
  reply.clearCookie('__session', clearOpts)
  reply.clearCookie('__refresh', clearOpts)

  if (!s && !r) return reply.redirect(`${targetOrigin}${dest}`)

  const token = encrypt({ s, r, p: dest, exp: Date.now() + TTL * 1000 })
  return reply.redirect(`${targetOrigin}/_bridge?t=${token}`)
})

app.get('/import', async (req, reply) => {
  const { t } = req.query
  let data
  try {
    data = decrypt(t)
  } catch {
    return reply.code(400).send('invalid token')
  }

  if (Date.now() > data.exp) return reply.code(400).send('expired token')

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

  return reply.redirect(safePath(data.p) || '/')
})

app.listen({ port: 3099, host: '0.0.0.0' })
