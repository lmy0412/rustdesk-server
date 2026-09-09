import { useEffect, useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { useAuth } from '../auth/AuthContext'
import { Alert, errorMessage } from '../components/Ui'

export function LoginPage() {
  const { initializing, user, login, loginWithOidc } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [oidcLoading, setOidcLoading] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const oidcError = params.get('error')
    if (oidcError) setError(`OIDC 登录失败：${oidcError}`)
  }, [location.search])

  if (!initializing && user) return <Navigate to="/dashboard" replace />

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      await login(username, password)
      const from = (location.state as { from?: string } | null)?.from ?? '/dashboard'
      navigate(from, { replace: true })
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setSubmitting(false)
    }
  }

  async function handleOidc() {
    setError('')
    setOidcLoading(true)
    try {
      await loginWithOidc()
    } catch (caught) {
      setError(errorMessage(caught))
      setOidcLoading(false)
    }
  }

  return (
    <main className="login-page">
      <section className="login-visual" aria-label="RustDesk 管理控制台介绍">
        <div className="login-orbit" aria-hidden="true"><span /></div>
        <div className="login-copy">
          <p className="eyebrow">安全 · 自托管 · 可观测</p>
          <h1>掌控每一台<br />远程设备</h1>
          <p>统一管理设备、成员、许可证与安全策略，所有管理流量留在您的基础设施中。</p>
        </div>
      </section>
      <section className="login-panel">
        <div className="login-card">
          <div className="brand brand-login">
            <span className="brand-mark">R</span>
            <div><strong>RustDesk</strong><small>Server Console</small></div>
          </div>
          <header>
            <p className="eyebrow">欢迎回来</p>
            <h2>登录管理控制台</h2>
            <p>使用管理员分配的账号继续。</p>
          </header>
          {error && <Alert>{error}</Alert>}
          <form onSubmit={handleSubmit} className="form-stack">
            <label>
              用户名
              <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required autoFocus />
            </label>
            <label>
              密码
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
            </label>
            <button className="button button-primary button-block" disabled={submitting || initializing}>
              {submitting ? '正在登录…' : '登录'}
            </button>
          </form>
          <div className="divider"><span>或</span></div>
          <button className="button button-secondary button-block" onClick={() => void handleOidc()} disabled={oidcLoading || initializing}>
            {oidcLoading ? '正在连接身份提供商…' : '使用 OIDC 登录'}
          </button>
          <p className="login-footnote">登录即表示您同意遵守组织的安全策略。</p>
        </div>
      </section>
    </main>
  )
}
