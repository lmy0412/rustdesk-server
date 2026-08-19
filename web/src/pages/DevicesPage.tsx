import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { apiRequest } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Alert, Empty, Loading, PageHeader, Pagination, StatusPill, errorMessage, formatDate } from '../components/Ui'
import type { Device, DeviceListResponse } from '../types'

type SortBy = 'device_id' | 'alias' | 'hostname' | 'os' | 'status' | 'last_seen'
type SortDir = 'asc' | 'desc'

export function DevicesPage() {
  const { user } = useAuth()
  const [data, setData] = useState<DeviceListResponse | null>(null)
  const [draftQuery, setDraftQuery] = useState('')
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('')
  const [tag, setTag] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [sortBy, setSortBy] = useState<SortBy>('last_seen')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [addTags, setAddTags] = useState('')
  const [removeTags, setRemoveTags] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(true)
  const [reload, setReload] = useState(0)
  const canWrite = user?.role !== 'viewer'

  useEffect(() => {
    let active = true
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
      sort_by: sortBy,
      sort_dir: sortDir,
    })
    if (query) params.set('q', query)
    if (status) params.set('status', status)
    if (tag) params.set('tag', tag)
    setLoading(true)
    setError('')
    void apiRequest<DeviceListResponse>(`/api/devices?${params}`).then(
      (response) => {
        if (active) {
          setData(response)
          setSelected(new Set())
          setLoading(false)
        }
      },
      (caught) => {
        if (active) {
          setError(errorMessage(caught))
          setLoading(false)
        }
      },
    )
    return () => { active = false }
  }, [page, pageSize, query, reload, sortBy, sortDir, status, tag])

  const allSelected = useMemo(
    () => Boolean(data?.items.length) && data!.items.every((device) => selected.has(device.device_id)),
    [data, selected],
  )

  function submitFilter(event: FormEvent) {
    event.preventDefault()
    setPage(1)
    setQuery(draftQuery.trim())
  }

  function toggle(deviceId: string) {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(deviceId)) next.delete(deviceId)
      else next.add(deviceId)
      return next
    })
  }

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(data?.items.map((device) => device.device_id) ?? []))
  }

  async function applyTags() {
    setError('')
    setNotice('')
    try {
      const response = await apiRequest<{ matched_devices: number; added_relations: number; removed_relations: number }>(
        '/api/devices/batch-tag',
        {
          method: 'POST',
          body: JSON.stringify({
            device_ids: [...selected],
            add_tags: splitTags(addTags),
            remove_tags: splitTags(removeTags),
          }),
        },
      )
      setNotice(`已更新 ${response.matched_devices} 台设备，新增 ${response.added_relations} 个标签关系，移除 ${response.removed_relations} 个。`)
      setAddTags('')
      setRemoveTags('')
      setReload((value) => value + 1)
    } catch (caught) {
      setError(errorMessage(caught))
    }
  }

  async function deactivateSelected() {
    if (!window.confirm(`确认停用选中的 ${selected.size} 台设备？设备将无法继续连接。`)) return
    setError('')
    setNotice('')
    try {
      await Promise.all([...selected].map((id) => apiRequest(`/api/license/devices/${encodeURIComponent(id)}/inactive`, { method: 'POST' })))
      setNotice(`已停用 ${selected.size} 台设备。`)
      setReload((value) => value + 1)
    } catch (caught) {
      setError(errorMessage(caught))
    }
  }

  return (
    <>
      <PageHeader title="设备管理" description="搜索、筛选并批量管理已登记的 RustDesk 设备。" />
      {error && <Alert>{error}</Alert>}
      {notice && <Alert tone="success">{notice}</Alert>}
      <section className="panel filters">
        <form onSubmit={submitFilter} className="filter-row">
          <label className="grow">搜索设备<input value={draftQuery} onChange={(event) => setDraftQuery(event.target.value)} placeholder="设备 ID、别名或主机名" /></label>
          <label>状态<select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1) }}><option value="">全部</option><option value="online">在线</option><option value="offline">离线</option><option value="inactive">已停用</option></select></label>
          <label>标签<input value={tag} onChange={(event) => setTag(event.target.value)} onBlur={() => setPage(1)} placeholder="精确标签" /></label>
          <button className="button button-primary">查询</button>
        </form>
        <div className="filter-row compact">
          <label>排序字段<select value={sortBy} onChange={(event) => { setSortBy(event.target.value as SortBy); setPage(1) }}><option value="last_seen">最后在线</option><option value="device_id">设备 ID</option><option value="alias">别名</option><option value="hostname">主机名</option><option value="os">系统</option><option value="status">状态</option></select></label>
          <label>方向<select value={sortDir} onChange={(event) => { setSortDir(event.target.value as SortDir); setPage(1) }}><option value="desc">降序</option><option value="asc">升序</option></select></label>
          <label>每页<select value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1) }}><option value="25">25</option><option value="50">50</option><option value="100">100</option></select></label>
        </div>
      </section>

      {canWrite && selected.size > 0 && (
        <section className="panel batch-bar" aria-label="批量操作">
          <strong>已选择 {selected.size} 台</strong>
          <input aria-label="要添加的标签" value={addTags} onChange={(event) => setAddTags(event.target.value)} placeholder="添加标签，逗号分隔" />
          <input aria-label="要移除的标签" value={removeTags} onChange={(event) => setRemoveTags(event.target.value)} placeholder="移除标签，逗号分隔" />
          <button className="button button-secondary" onClick={() => void applyTags()} disabled={!addTags.trim() && !removeTags.trim()}>应用标签</button>
          {user?.role === 'admin' && <button className="button button-danger" onClick={() => void deactivateSelected()}>批量停用</button>}
        </section>
      )}

      <section className="panel table-panel">
        {loading ? <Loading /> : !data?.items.length ? <Empty>没有符合条件的设备。</Empty> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th className="check">{canWrite && <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label="选择当前页全部设备" />}</th><th>设备</th><th>状态</th><th>系统</th><th>标签</th><th>归属</th><th>最后在线</th></tr></thead>
              <tbody>{data.items.map((device) => <DeviceRow key={device.device_id} device={device} selected={selected.has(device.device_id)} canWrite={canWrite} onToggle={() => toggle(device.device_id)} />)}</tbody>
            </table>
          </div>
        )}
        {data && <Pagination page={page} pageSize={pageSize} total={data.total} onChange={setPage} />}
      </section>
    </>
  )
}

function DeviceRow({ device, selected, canWrite, onToggle }: { device: Device; selected: boolean; canWrite: boolean; onToggle: () => void }) {
  return (
    <tr>
      <td className="check">{canWrite && <input type="checkbox" checked={selected} onChange={onToggle} aria-label={`选择设备 ${device.device_id}`} />}</td>
      <td><strong>{device.alias || device.hostname || device.device_id}</strong><small className="cell-subtitle">{device.device_id}{device.alias && device.hostname ? ` · ${device.hostname}` : ''}</small></td>
      <td><StatusPill value={device.status} /></td>
      <td>{device.os || '—'}</td>
      <td><div className="tags">{device.tags.length ? device.tags.map((value) => <span key={value}>{value}</span>) : '—'}</div></td>
      <td>{device.owner_user_id ? `用户 #${device.owner_user_id}` : '未分配'}</td>
      <td>{formatDate(device.last_seen)}</td>
    </tr>
  )
}

function splitTags(value: string): string[] {
  return [...new Set(value.split(/[,，]/).map((item) => item.trim()).filter(Boolean))]
}
