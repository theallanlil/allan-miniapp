// /api/verify.js
// Черновая проверка токена: безопасно принимает JWT,
// декодирует header/payload (БЕЗ криптопроверки подписи — для dev),
// и возвращает payload. Для продакшна обязательно добавить верификацию подписи.

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Use POST { token }' })
    }

    const { token } = req.body || {}
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ error: 'No token' })
    }

    const parts = token.split('.')
    if (parts.length !== 3) {
      return res.status(400).json({ error: 'Invalid JWT format' })
    }

    const [h, p] = parts
    const decode = (b64) =>
      JSON.parse(Buffer.from(b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'))

    const header = decode(h)
    const payload = decode(p)

    // TODO (prod): верифицировать подпись по публичным ключам Farcaster
    // здесь только возвращаем payload для наглядности
    return res.status(200).json({ ok: true, header, payload, note: 'Signature not verified (dev mode)' })
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) })
  }
}

