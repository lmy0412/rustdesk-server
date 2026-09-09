import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  beginOidcLogin,
  clearSession,
  login as loginRequest,
  logout as logoutRequest,
  restoreSession,
  subscribeToken,
  subscribeUnauthorized,
} from '../api/client'
import type { SessionUser } from '../types'
import { decodeSessionUser } from './token'

interface AuthValue {
  initializing: boolean
  user: SessionUser | null
  login: (username: string, password: string) => Promise<void>
  loginWithOidc: () => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [initializing, setInitializing] = useState(true)
  const [user, setUser] = useState<SessionUser | null>(null)

  useEffect(() => {
    let active = true
    const unsubscribe = subscribeUnauthorized(() => setUser(null))
    const unsubscribeToken = subscribeToken((token) => {
      if (active) setUser(token ? decodeSessionUser(token) : null)
    })
    void restoreSession().then((token) => {
      if (active) {
        setUser(token ? decodeSessionUser(token) : null)
        setInitializing(false)
      }
    })
    return () => {
      active = false
      unsubscribe()
      unsubscribeToken()
    }
  }, [])

  const value = useMemo<AuthValue>(
    () => ({
      initializing,
      user,
      async login(username, password) {
        const token = await loginRequest(username, password)
        const nextUser = decodeSessionUser(token)
        if (!nextUser) {
          clearSession()
          throw new Error('登录令牌缺少有效用户信息')
        }
        setUser(nextUser)
      },
      async loginWithOidc() {
        const url = await beginOidcLogin()
        window.location.assign(url)
      },
      async logout() {
        await logoutRequest()
        setUser(null)
      },
    }),
    [initializing, user],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth 必须在 AuthProvider 内使用')
  return value
}
