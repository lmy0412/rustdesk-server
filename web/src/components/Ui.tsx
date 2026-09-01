import type { ReactNode } from 'react'

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description: string
  actions?: ReactNode
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">管理中心</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  )
}

export function Alert({ children, tone = 'error' }: { children: ReactNode; tone?: 'error' | 'success' | 'info' }) {
  return (
    <div className={`alert alert-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  )
}

export function Loading({ label = '正在加载' }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Pagination({
  page,
  pageSize,
  total,
  onChange,
}: {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <nav className="pagination" aria-label="分页">
      <span>
        共 {total} 条 · 第 {page}/{pages} 页
      </span>
      <div>
        <button className="button button-quiet" disabled={page <= 1} onClick={() => onChange(page - 1)}>
          上一页
        </button>
        <button className="button button-quiet" disabled={page >= pages} onClick={() => onChange(page + 1)}>
          下一页
        </button>
      </div>
    </nav>
  )
}

export function StatusPill({ value }: { value: string }) {
  const tone = value === 'online' || value === 'active' ? 'good' : value === 'inactive' || value === 'unlicensed' ? 'muted' : 'warn'
  const labels: Record<string, string> = {
    online: '在线',
    offline: '离线',
    inactive: '已停用',
    active: '有效',
    unlicensed: '未激活',
  }
  return <span className={`status status-${tone}`}>{labels[value] ?? value}</span>
}

export function formatDate(value: string | number | null | undefined): string {
  if (value == null || value === '') return '—'
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(`${value}${value.endsWith('Z') ? '' : 'Z'}`)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '发生未知错误'
}
