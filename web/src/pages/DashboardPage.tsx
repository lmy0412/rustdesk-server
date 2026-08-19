import { useEffect, useState } from 'react'
import { apiRequest } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Alert, Loading, PageHeader, StatusPill, errorMessage, formatDate } from '../components/Ui'
import type { DeviceListResponse, HealthResponse, LicenseStatus, LicenseUsage } from '../types'

interface DashboardState {
  health: HealthResponse
  devices: DeviceListResponse
  online: DeviceListResponse
  license: LicenseStatus
  usage: LicenseUsage | null
}

export function DashboardPage() {
  const { user } = useAuth()
  const [data, setData] = useState<DashboardState | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    async function load() {
      try {
        const [health, devices, online, license, usage] = await Promise.all([
          apiRequest<HealthResponse>('/api/health'),
          apiRequest<DeviceListResponse>('/api/devices?page=1&page_size=1'),
          apiRequest<DeviceListResponse>('/api/devices?status=online&page=1&page_size=1'),
          apiRequest<LicenseStatus>('/api/license/status'),
          user?.role === 'admin' ? apiRequest<LicenseUsage>('/api/license/usage') : Promise.resolve(null),
        ])
        if (active) setData({ health, devices, online, license, usage })
      } catch (caught) {
        if (active) setError(errorMessage(caught))
      }
    }
    void load()
    return () => { active = false }
  }, [user?.role])

  return (
    <>
      <PageHeader title="仪表盘" description="快速了解服务、设备和许可证的当前状态。" />
      {error && <Alert>{error}</Alert>}
      {!data ? <Loading /> : (
        <>
          <section className="metric-grid" aria-label="关键指标">
            <Metric label="服务状态" value={data.health.status === 'ok' ? '运行正常' : data.health.status} hint={`数据库：${data.health.db}`} accent="cyan" />
            <Metric label="在线设备" value={String(data.online.total)} hint={`占全部 ${data.devices.total} 台`} accent="green" />
            <Metric label="活跃连接" value="—" hint="暂无监控接口" accent="violet" />
            <Metric label="实时带宽" value="—" hint="暂无监控接口" accent="orange" />
          </section>
          <section className="dashboard-grid">
            <article className="panel license-summary">
              <div className="panel-heading">
                <div><p className="eyebrow">License</p><h2>许可证状态</h2></div>
                <StatusPill value={data.license.active ? 'active' : 'unlicensed'} />
              </div>
              <dl className="detail-grid">
                <div><dt>授权主体</dt><dd>{data.license.issued_to ?? '未激活'}</dd></div>
                <div><dt>设备额度</dt><dd>{data.license.max_devices ?? '—'}</dd></div>
                <div><dt>用户额度</dt><dd>{data.license.max_users ?? '—'}</dd></div>
                <div><dt>到期时间</dt><dd>{formatDate(data.license.expires_at)}</dd></div>
              </dl>
              {data.license.days_remaining != null && <p className="subtle">剩余 {data.license.days_remaining} 天</p>}
            </article>
            <article className="panel">
              <div className="panel-heading"><div><p className="eyebrow">Capacity</p><h2>资源用量</h2></div></div>
              {data.usage ? (
                <div className="usage-list">
                  <Usage label="设备" value={data.usage.current_devices} max={data.usage.max_devices} pct={data.usage.device_usage_pct} />
                  <Usage label="用户" value={data.usage.current_users} max={data.usage.max_users} pct={data.usage.user_usage_pct} />
                </div>
              ) : <p className="empty-inline">仅管理员可查看许可证用量。</p>}
            </article>
          </section>
        </>
      )}
    </>
  )
}

function Metric({ label, value, hint, accent }: { label: string; value: string; hint: string; accent: string }) {
  return <article className={`metric metric-${accent}`}><span>{label}</span><strong>{value}</strong><small>{hint}</small></article>
}

function Usage({ label, value, max, pct }: { label: string; value: number; max: number; pct: number }) {
  const width = Math.max(0, Math.min(100, pct))
  return (
    <div className="usage-row">
      <div><span>{label}</span><strong>{value} / {max || '—'}</strong></div>
      <progress max={100} value={width} aria-label={`${label}用量`} />
    </div>
  )
}
