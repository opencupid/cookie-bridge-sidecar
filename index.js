import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'

const app = Fastify()
app.register(cookie)

const NEW_ORIGIN = `https://${process.env.NEW_DOMAIN}`
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

  if (!s && !r) return reply.code(204).send()

  const token = encrypt({ s, r, p: `/${path}`, exp: Date.now() + TTL * 1000 })
  return reply.redirect(`${NEW_ORIGIN}/_bridge?t=${token}`)
})

app.get('/import', async (req, reply) => {
  const { t } = req.query
  let data
  try {
    data = decrypt(t)
  } catch {
    return reply.redirect(NEW_ORIGIN)
  }

  if (Date.now() > data.exp) return reply.redirect(NEW_ORIGIN)

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

  return reply.redirect(`${NEW_ORIGIN}${data.p || '/'}`)
})

app.listen({ port: 3099, host: '0.0.0.0' })
