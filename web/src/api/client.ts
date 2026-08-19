export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

interface RequestOptions {
  auth?: boolean
  retry?: boolean
}

interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

interface LoginResponse extends TokenResponse {
  refresh_token: string
}

let accessToken: string | null = null
let refreshPromise: Promise<string> | null = null
const unauthorizedListeners = new Set<() => void>()
const tokenListeners = new Set<(token: string | null) => void>()

const REQUEST_TIMEOUT_MS = 15_000

export function subscribeUnauthorized(listener: () => void): () => void {
  unauthorizedListeners.add(listener)
  return () => unauthorizedListeners.delete(listener)
}

export function subscribeToken(listener: (token: string | null) => void): () => void {
  tokenListeners.add(listener)
  return () => tokenListeners.delete(listener)
}

export function clearSession(): void {
  setAccessToken(null)
}

export async function login(username: string, password: string): Promise<string> {
  const response = await request<LoginResponse>(
    '/api/auth/login',
    {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    },
    { auth: false, retry: false },
  )
  setAccessToken(response.access_token)
  return response.access_token
}

export async function beginOidcLogin(): Promise<string> {
  const response = await request<{ authorization_url: string }>(
    '/api/auth/oidc/login',
    {},
    { auth: false, retry: false },
  )
  return response.authorization_url
}

export async function restoreSession(): Promise<string | null> {
  try {
    return await refreshAccessToken()
  } catch {
    clearSession()
    return null
  }
}

export async function logout(): Promise<void> {
  try {
    await request<void>('/api/auth/logout', { method: 'POST' }, { retry: false })
  } finally {
    clearSession()
  }
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  return request<T>(path, init, { auth: true, retry: true })
}

async function request<T>(
  path: string,
  init: RequestInit,
  options: RequestOptions,
): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body != null && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  if (options.auth !== false && accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`)
  }

  let response: Response
  try {
    response = await fetchWithTimeout(path, {
      ...init,
      headers,
      credentials: 'same-origin',
    })
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError('无法连接服务器，请检查网络后重试', 0)
  }

  if (response.status === 401 && options.auth !== false && options.retry !== false) {
    try {
      await refreshAccessToken()
      return request<T>(path, init, { ...options, retry: false })
    } catch {
      clearSession()
      unauthorizedListeners.forEach((listener) => listener())
      throw new ApiError('登录状态已失效，请重新登录', 401)
    }
  }

  if (!response.ok) {
    throw new ApiError(await responseMessage(response), response.status)
  }
  if (response.status === 204) return undefined as T
  const text = await response.text()
  if (!text) return undefined as T
  try {
    return JSON.parse(text) as T
  } catch {
    throw new ApiError('服务器返回了无法解析的数据', 502)
  }
}

async function refreshAccessToken(): Promise<string> {
  if (refreshPromise) return refreshPromise
  refreshPromise = (async () => {
    let response: Response
    try {
      response = await fetchWithTimeout('/api/auth/refresh', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      })
    } catch (error) {
      if (error instanceof ApiError) throw error
      throw new ApiError('无法连接服务器，请检查网络后重试', 0)
    }
    if (!response.ok) throw new ApiError(await responseMessage(response), response.status)
    const payload = (await response.json()) as TokenResponse
    if (!payload.access_token) throw new ApiError('服务器返回了无效会话', 500)
    setAccessToken(payload.access_token)
    return payload.access_token
  })()
  try {
    return await refreshPromise
  } finally {
    refreshPromise = null
  }
}

function setAccessToken(token: string | null): void {
  accessToken = token
  tokenListeners.forEach((listener) => listener(token))
}

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit): Promise<Response> {
  const controller = new AbortController()
  let timedOut = false
  const abortFromCaller = () => controller.abort(init.signal?.reason)
  if (init.signal?.aborted) abortFromCaller()
  else init.signal?.addEventListener('abort', abortFromCaller, { once: true })
  const timer = globalThis.setTimeout(() => {
    timedOut = true
    controller.abort()
  }, REQUEST_TIMEOUT_MS)
  try {
    return await fetch(input, { ...init, signal: controller.signal })
  } catch (error) {
    if (timedOut) throw new ApiError('请求超时，请稍后重试', 0)
    throw error
  } finally {
    globalThis.clearTimeout(timer)
    init.signal?.removeEventListener('abort', abortFromCaller)
  }
}

async function responseMessage(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { error?: unknown; message?: unknown }
    if (typeof payload.error === 'string') return payload.error
    if (typeof payload.message === 'string') return payload.message
  } catch {
    // 非 JSON 错误响应使用状态码兜底。
  }
  return `请求失败（HTTP ${response.status}）`
}
