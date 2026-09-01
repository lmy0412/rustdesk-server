import { describe, expect, it } from 'vitest'
import { decodeSessionUser } from './token'

function token(payload: unknown): string {
  const encoded = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `header.${encoded}.signature`
}

describe('decodeSessionUser', () => {
  it('读取安全整数用户和有效角色', () => {
    expect(decodeSessionUser(token({ sub: 7, role: 'admin' }))).toEqual({ id: 7, role: 'admin' })
  })

  it('拒绝损坏、越界或未知角色的声明', () => {
    expect(decodeSessionUser('broken')).toBeNull()
    expect(decodeSessionUser(token({ sub: Number.MAX_SAFE_INTEGER + 1, role: 'admin' }))).toBeNull()
    expect(decodeSessionUser(token({ sub: 7, role: 'owner' }))).toBeNull()
  })
})
