// /api/verify.js
// Верификация JWT Farcaster по подписи RS256 с JWKS (Node.js crypto)

const JWKS_URL = 'https://api.warpcast.com/v2/jwks'
const EXPECTED_AUD = 'https://allan-miniapp.vercel.app/'

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Use POST with JSON { token }' })
    }

    // Тело запроса может прийти строкой — разбираем надёжно
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body
    const token = body?.token
    if (!token) return res.status(400).json({ error: 'No token' })

    const parts = String(token).split('.')
    if (parts.length !== 3) return res.status(400).json({ error: 'Invalid JWT format' })

    const [hB64, pB64, sB64] = parts

    // Декод header/payload (base64url → JSON)
    const b64urlToBuf = (b64) =>
      Buffer.from(b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    const jsonOf = (b64) => JSON.parse(b64urlToBuf(b64).toString('utf8'))

    const header = jsonOf(hB64)
    const payload = jsonOf(pB64)
    const signature = b64urlToBuf(sB64)

    // Базовые проверки до криптографии
    const now = Math.floor(Date.now() / 1000)
    const exp = Number(payload?.exp || 0)
    const aud = String(payload?.aud || '')

    if (aud !== EXPECTED_AUD) {
      return res.status(401).json({ ok: false, error: 'aud mismatch', aud, EXPECTED_AUD })
    }
    if (!exp || exp <= now) {
      return res.status(401).json({ ok: false, error: 'token expired', exp, now })
    }
    if (header?.alg !== 'RS256') {
      return res.status(400).json({ ok: false, error: `Unsupported alg: ${header?.alg}` })
    }

    // Загружаем JWKS и находим ключ по kid
    const jwksResp = await fetch(JWKS_URL)
    const jwksJson = await jwksResp.json()
    const keys = jwksJson?.keys || []
    const jwk = keys.find((k) => k.kid === header.kid)
    if (!jwk) {
      return res.status(401).json({ ok: false, error: 'Unknown key ID', kid: header?.kid })
    }

    // Node crypto: создаём публичный ключ из JWK и проверяем подпись
    const { createPublicKey, verify } = await import('node:crypto')
    const keyObject = createPublicKey({ key: jwk, format: 'jwk' }) // ← поддерживается Node 16+
    const data = Buffer.from(`${hB64}.${pB64}`) // именно base64url-пары в ASCII/UTF-8

    const isValid = verify('RSA-SHA256', data, keyObject, signature)

    return res.status(200).json({
      ok: !!isValid,
      header,
      payload,
      note: isValid ? '✅ Signature verified (RS256, JWKS via Node crypto)' : '❌ Invalid signature'
    })
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) })
  }
}
