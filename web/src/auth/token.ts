import type { Role, SessionUser } from '../types'

interface JwtPayload {
  sub?: unknown
  role?: unknown
  exp?: unknown
}

export function decodeSessionUser(token: string): SessionUser | null {
  const parts = token.split('.')
  if (parts.length !== 3 || !parts[1]) return null

  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const payload = JSON.parse(atob(base64)) as JwtPayload
    if (
      typeof payload.sub !== 'number' ||
      !Number.isSafeInteger(payload.sub) ||
      payload.sub < 1 ||
      !isRole(payload.role)
    ) {
      return null
    }
    return { id: payload.sub, role: payload.role }
  } catch {
    return null
  }
}

function isRole(value: unknown): value is Role {
  return value === 'admin' || value === 'user' || value === 'viewer'
}
