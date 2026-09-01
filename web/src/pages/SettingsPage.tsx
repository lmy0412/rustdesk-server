import { useEffect, useState, type FormEvent } from 'react'
import { apiRequest } from '../api/client'
import { Alert, Loading, PageHeader, errorMessage } from '../components/Ui'
import type { SecurityPolicy } from '../types'

export function SettingsPage() {
  const [policy, setPolicy] = useState<SecurityPolicy | null>(null)
  const [cidrs, setCidrs] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let active = true
    void apiRequest<SecurityPolicy>('/api/security/policies').then(
      (response) => { if (active) { setPolicy(response); setCidrs(response.allowed_admin_cidrs.join('\n')) } },
      (caught) => { if (active) setError(errorMessage(caught)) },
    )
    return () => { active = false }
  }, [])

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!policy) return
    setSaving(true)
    setError('')
    setNotice('')
    try {
      const next = await apiRequest<SecurityPolicy>('/api/security/policies', {
        method: 'PUT',
        body: JSON.stringify({ ...policy, allowed_admin_cidrs: cidrs.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) }),
      })
      setPolicy(next)
      setCidrs(next.allowed_admin_cidrs.join('\n'))
      setNotice('安全策略已生效。')
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <PageHeader title="系统设置" description="调整在线安全策略并查看外部服务配置方式。" />
      {error && <Alert>{error}</Alert>}
      {notice && <Alert tone="success">{notice}</Alert>}
      {!policy ? <Loading /> : (
        <section className="panel form-panel">
          <div className="panel-heading"><div><p className="eyebrow">Security policy</p><h2>安全策略</h2><p>保存前会由服务端校验数值范围和管理员来源网段。</p></div></div>
          <form onSubmit={save} className="form-grid settings-grid">
            <label>密码最小长度<input type="number" min="1" value={policy.password_min_length} onChange={(event) => setPolicy({ ...policy, password_min_length: Number(event.target.value) })} /></label>
            <label>最大登录失败次数<input type="number" min="1" value={policy.login_max_failures} onChange={(event) => setPolicy({ ...policy, login_max_failures: Number(event.target.value) })} /></label>
            <label>锁定时长（分钟）<input type="number" min="1" value={policy.login_lock_minutes} onChange={(event) => setPolicy({ ...policy, login_lock_minutes: Number(event.target.value) })} /></label>
            <label>会话超时（分钟）<input type="number" min="1" value={policy.session_timeout_minutes} onChange={(event) => setPolicy({ ...policy, session_timeout_minutes: Number(event.target.value) })} /></label>
            <label>审计保留（天）<input type="number" min="1" value={policy.audit_retention_days} onChange={(event) => setPolicy({ ...policy, audit_retention_days: Number(event.target.value) })} /></label>
            <label className="check-label"><input type="checkbox" checked={policy.password_require_number} onChange={(event) => setPolicy({ ...policy, password_require_number: event.target.checked })} />密码必须包含数字</label>
            <label className="check-label"><input type="checkbox" checked={policy.password_require_symbol} onChange={(event) => setPolicy({ ...policy, password_require_symbol: event.target.checked })} />密码必须包含符号</label>
            <label className="full">管理员允许网段（每行一个 CIDR）<textarea rows={4} value={cidrs} onChange={(event) => setCidrs(event.target.value)} placeholder="留空表示不限制" /></label>
            <div className="form-actions full"><button className="button button-primary" disabled={saving}>{saving ? '正在保存…' : '保存安全策略'}</button></div>
          </form>
        </section>
      )}
      <section className="settings-cards">
        <article className="panel"><p className="eyebrow">Identity</p><h2>OIDC</h2><p>OIDC 的 issuer、client ID、回调地址和密钥由 <code>config.toml</code> 或环境变量管理。控制台不会读取或回显 client secret。</p><span className="config-badge">服务端配置</span></article>
        <article className="panel"><p className="eyebrow">Delivery</p><h2>SMTP</h2><p>SMTP 主机、发件人和凭据继续由服务端配置管理，避免高权限密钥暴露给浏览器。</p><span className="config-badge">服务端配置</span></article>
      </section>
    </>
  )
}
