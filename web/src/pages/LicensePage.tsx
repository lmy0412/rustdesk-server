import { useEffect, useState, type FormEvent } from 'react'
import { apiRequest } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Alert, Loading, PageHeader, StatusPill, errorMessage, formatDate } from '../components/Ui'
import type { LicenseStatus, LicenseUsage } from '../types'

export function LicensePage() {
  const { user } = useAuth()
  const [status, setStatus] = useState<LicenseStatus | null>(null)
  const [usage, setUsage] = useState<LicenseUsage | null>(null)
  const [licenseKey, setLicenseKey] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let active = true
    setLoading(true)
    const requests: [Promise<LicenseStatus>, Promise<LicenseUsage | null>] = [
      apiRequest('/api/license/status'),
      user?.role === 'admin' ? apiRequest('/api/license/usage') : Promise.resolve(null),
    ]
    void Promise.all(requests).then(
      ([nextStatus, nextUsage]) => { if (active) { setStatus(nextStatus); setUsage(nextUsage); setLoading(false) } },
      (caught) => { if (active) { setError(errorMessage(caught)); setLoading(false) } },
    )
    return () => { active = false }
  }, [reload, user?.role])

  async function upload(event: FormEvent) {
    event.preventDefault()
    setUploading(true)
    setError('')
    try {
      await apiRequest('/api/license/upload', { method: 'POST', body: JSON.stringify({ license_key: licenseKey.trim() }) })
      setLicenseKey('')
      setNotice('许可证已验证并激活。')
      setReload((value) => value + 1)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setUploading(false)
    }
  }

  return (
    <>
      <PageHeader title="许可证" description="查看授权状态、容量用量并安全更新许可证。" />
      {error && <Alert>{error}</Alert>}
      {notice && <Alert tone="success">{notice}</Alert>}
      {loading || !status ? <Loading /> : (
        <section className="dashboard-grid">
          <article className="panel">
            <div className="panel-heading"><div><p className="eyebrow">Entitlement</p><h2>授权信息</h2></div><StatusPill value={status.active ? 'active' : 'unlicensed'} /></div>
            <dl className="detail-grid">
              <div><dt>授权主体</dt><dd>{status.issued_to ?? '未激活'}</dd></div>
              <div><dt>签发时间</dt><dd>{formatDate(status.issued_at)}</dd></div>
              <div><dt>到期时间</dt><dd>{formatDate(status.expires_at)}</dd></div>
              <div><dt>剩余天数</dt><dd>{status.days_remaining ?? '—'}</dd></div>
              <div><dt>设备额度</dt><dd>{status.max_devices ?? '—'}</dd></div>
              <div><dt>用户额度</dt><dd>{status.max_users ?? '—'}</dd></div>
            </dl>
          </article>
          <article className="panel">
            <div className="panel-heading"><div><p className="eyebrow">Usage</p><h2>当前用量</h2></div></div>
            {usage ? <div className="license-usage">
              <UsageBar label="设备" current={usage.current_devices} max={usage.max_devices} />
              <UsageBar label="用户" current={usage.current_users} max={usage.max_users} />
              <div className="mini-stats"><span>在线 <strong>{usage.online_devices}</strong></span><span>离线 <strong>{usage.offline_devices}</strong></span><span>停用 <strong>{usage.inactive_devices}</strong></span></div>
            </div> : <p className="empty-inline">仅管理员可查看详细用量。</p>}
          </article>
        </section>
      )}
      {user?.role === 'admin' && (
        <section className="panel form-panel">
          <div className="panel-heading"><div><p className="eyebrow">Activation</p><h2>上传许可证</h2><p>许可证仅发送到当前服务器，不会保存在浏览器中。</p></div></div>
          <form onSubmit={upload} className="form-stack">
            <label>许可证密钥<textarea rows={5} value={licenseKey} onChange={(event) => setLicenseKey(event.target.value)} placeholder="粘贴完整许可证密钥" required /></label>
            <div className="form-actions"><button className="button button-primary" disabled={uploading || !licenseKey.trim()}>{uploading ? '正在验证…' : '验证并激活'}</button></div>
          </form>
        </section>
      )}
    </>
  )
}

function UsageBar({ label, current, max }: { label: string; current: number; max: number }) {
  return <div className="usage-row"><div><span>{label}</span><strong>{current} / {max || '—'}</strong></div><progress max={max || 1} value={current} aria-label={`${label}用量`} /></div>
}
