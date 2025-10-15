// /api/verify.js — полная верификация JWT подписи Farcaster
import * as jose from 'jose'

const JWKS_URL = 'https://api.warpcast.com/v2/jwks'
const EXPECTED_AUD = 'https://allan-miniapp.vercel.app/'

const JWKS = jose.createRemoteJWKSet(new URL(JWKS_URL))

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST { token }' })
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body
    const token = body?.token
    if (!token) return res.status(400).json({ error: 'No token' })

    const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, {
      audience: EXPECTED_AUD,
      issuer: 'farcaster'
    })

    return res.status(200).json({ ok: true, header: protectedHeader, payload })
  } catch (e) {
    return res.status(401).json({ ok: false, error: e.message })
  }
}
