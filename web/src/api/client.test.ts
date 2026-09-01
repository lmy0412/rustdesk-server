import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiRequest, clearSession, subscribeToken } from './client'

describe('API client', () => {
  beforeEach(() => {
    clearSession()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('401 时只刷新一次并用新 Bearer token 重放请求', async () => {
    const token = jwt({ sub: 1, role: 'admin' })
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ error: 'expired' }, 401))
      .mockResolvedValueOnce(jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 3600 }))
      .mockResolvedValueOnce(jsonResponse({ items: [], total: 0 }))
    vi.stubGlobal('fetch', fetchMock)
    const observed: Array<string | null> = []
    const unsubscribe = subscribeToken((value) => observed.push(value))

    await expect(apiRequest('/api/devices')).resolves.toEqual({ items: [], total: 0 })
    unsubscribe()

    expect(fetchMock).toHaveBeenCalledTimes(3)
    const retryInit = fetchMock.mock.calls[2]?.[1]
    expect(new Headers(retryInit?.headers).get('Authorization')).toBe(`Bearer ${token}`)
    expect(observed).toContain(token)
  })

  it('把超时和损坏的成功响应转换为可显示错误', async () => {
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        }),
      ),
    )
    const pending = apiRequest('/api/devices')
    const timeoutAssertion = expect(pending).rejects.toMatchObject({ message: '请求超时，请稍后重试' })
    await vi.advanceTimersByTimeAsync(15_000)
    await timeoutAssertion

    vi.useRealTimers()
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(new Response('not-json', { status: 200 })))
    await expect(apiRequest('/api/devices')).rejects.toMatchObject({ message: '服务器返回了无法解析的数据', status: 502 })
  })
})

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

function jwt(payload: unknown): string {
  const encoded = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `header.${encoded}.signature`
}
