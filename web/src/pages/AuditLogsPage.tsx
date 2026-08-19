import { useEffect, useState, type FormEvent } from 'react'
import { apiRequest } from '../api/client'
import { Alert, Empty, Loading, PageHeader, Pagination, errorMessage, formatDate } from '../components/Ui'
import type { AuditLogResponse } from '../types'

export function AuditLogsPage() {
  const [data, setData] = useState<AuditLogResponse | null>(null)
  const [filters, setFilters] = useState({ action: '', targetType: '', userId: '', from: '', to: '' })
  const [applied, setApplied] = useState(filters)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const pageSize = 50

  useEffect(() => {
    let active = true
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (applied.action) params.set('action', applied.action)
    if (applied.targetType) params.set('target_type', applied.targetType)
    if (applied.userId) params.set('user_id', applied.userId)
    if (applied.from) params.set('from', new Date(applied.from).toISOString())
    if (applied.to) params.set('to', new Date(applied.to).toISOString())
    setLoading(true)
    setError('')
    void apiRequest<AuditLogResponse>(`/api/audit-logs?${params}`).then(
      (response) => { if (active) { setData(response); setLoading(false) } },
      (caught) => { if (active) { setError(errorMessage(caught)); setLoading(false) } },
    )
    return () => { active = false }
  }, [applied, page])

  function submit(event: FormEvent) {
    event.preventDefault()
    setPage(1)
    setApplied({ ...filters })
  }

  return (
    <>
      <PageHeader title="审计日志" description="按操作者、动作、资源和时间范围追踪管理活动。" />
      {error && <Alert>{error}</Alert>}
      <section className="panel filters">
        <form onSubmit={submit} className="filter-row wrap">
          <label>动作<input value={filters.action} onChange={(event) => setFilters({ ...filters, action: event.target.value })} placeholder="例如 user.create" /></label>
          <label>目标类型<input value={filters.targetType} onChange={(event) => setFilters({ ...filters, targetType: event.target.value })} placeholder="例如 device" /></label>
          <label>用户 ID<input type="number" min="1" value={filters.userId} onChange={(event) => setFilters({ ...filters, userId: event.target.value })} /></label>
          <label>开始时间<input type="datetime-local" value={filters.from} onChange={(event) => setFilters({ ...filters, from: event.target.value })} /></label>
          <label>结束时间<input type="datetime-local" value={filters.to} onChange={(event) => setFilters({ ...filters, to: event.target.value })} /></label>
          <button className="button button-primary">查询</button>
        </form>
      </section>
      <section className="panel table-panel">
        {loading ? <Loading /> : !data?.items.length ? <Empty>当前筛选条件下没有审计记录。</Empty> : (
          <div className="table-wrap"><table><thead><tr><th>时间</th><th>动作</th><th>操作者</th><th>目标</th><th>来源 IP</th><th>详情</th></tr></thead><tbody>{data.items.map((item) => (
            <tr key={item.id}><td>{formatDate(item.created_at)}</td><td><code>{item.action}</code></td><td>{item.user_id ? `用户 #${item.user_id}` : '系统'}</td><td>{item.target_type ?? '—'}{item.target_id ? ` / ${item.target_id}` : ''}</td><td>{item.ip_address ?? '—'}</td><td><code className="detail-code">{item.detail == null ? '—' : JSON.stringify(item.detail)}</code></td></tr>
          ))}</tbody></table></div>
        )}
        {data && <Pagination page={page} pageSize={pageSize} total={data.total} onChange={setPage} />}
      </section>
    </>
  )
}
