import { useEffect, useState, type FormEvent } from 'react'
import { apiRequest } from '../api/client'
import { Alert, Empty, Loading, PageHeader, Pagination, errorMessage, formatDate } from '../components/Ui'
import type { Role, UserListResponse, UserSummary } from '../types'

export function UsersPage() {
  const [data, setData] = useState<UserListResponse | null>(null)
  const [page, setPage] = useState(1)
  const [reload, setReload] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const pageSize = 20

  useEffect(() => {
    let active = true
    setLoading(true)
    setError('')
    void apiRequest<UserListResponse>(`/api/users?page=${page}&page_size=${pageSize}`).then(
      (response) => { if (active) { setData(response); setLoading(false) } },
      (caught) => { if (active) { setError(errorMessage(caught)); setLoading(false) } },
    )
    return () => { active = false }
  }, [page, reload])

  function changed(message: string) {
    setNotice(message)
    setShowCreate(false)
    setReload((value) => value + 1)
  }

  return (
    <>
      <PageHeader title="用户管理" description="创建成员、调整角色并控制账号状态。" actions={<button className="button button-primary" onClick={() => setShowCreate((value) => !value)}>{showCreate ? '取消' : '新建用户'}</button>} />
      {error && <Alert>{error}</Alert>}
      {notice && <Alert tone="success">{notice}</Alert>}
      {showCreate && <CreateUser onCreated={() => changed('用户已创建。')} onError={setError} />}
      <section className="panel table-panel">
        {loading ? <Loading /> : !data?.items.length ? <Empty>暂无用户。</Empty> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>用户</th><th>角色</th><th>状态</th><th>创建时间</th><th className="actions-cell">操作</th></tr></thead>
              <tbody>{data.items.map((item) => <UserRow key={item.id} user={item} onChanged={changed} onError={setError} />)}</tbody>
            </table>
          </div>
        )}
        {data && <Pagination page={page} pageSize={pageSize} total={data.total} onChange={setPage} />}
      </section>
    </>
  )
}

function CreateUser({ onCreated, onError }: { onCreated: () => void; onError: (message: string) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<Role>('user')
  const [saving, setSaving] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSaving(true)
    try {
      await apiRequest('/api/users', { method: 'POST', body: JSON.stringify({ username, password, email: email || null, role }) })
      onCreated()
    } catch (caught) {
      onError(errorMessage(caught))
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="panel form-panel">
      <div className="panel-heading"><div><p className="eyebrow">New member</p><h2>创建用户</h2></div></div>
      <form onSubmit={submit} className="form-grid">
        <label>用户名<input value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
        <label>邮箱<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
        <label>初始密码<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" required /></label>
        <label>角色<select value={role} onChange={(event) => setRole(event.target.value as Role)}><option value="user">用户</option><option value="viewer">只读</option><option value="admin">管理员</option></select></label>
        <div className="form-actions"><button className="button button-primary" disabled={saving}>{saving ? '正在创建…' : '创建用户'}</button></div>
      </form>
    </section>
  )
}

function UserRow({ user, onChanged, onError }: { user: UserSummary; onChanged: (message: string) => void; onError: (message: string) => void }) {
  const [role, setRole] = useState<Role>(user.role)
  const [active, setActive] = useState(user.is_active)
  const [saving, setSaving] = useState(false)
  const dirty = role !== user.role || active !== user.is_active

  async function save() {
    setSaving(true)
    try {
      await apiRequest(`/api/users/${user.id}`, { method: 'PUT', body: JSON.stringify({ email: null, role, is_active: active, password: null, force_logout: !active }) })
      onChanged(`用户 ${user.username} 已更新。`)
    } catch (caught) {
      onError(errorMessage(caught))
    } finally {
      setSaving(false)
    }
  }

  async function remove() {
    if (!window.confirm(`确认停用用户“${user.username}”？`)) return
    try {
      await apiRequest(`/api/users/${user.id}`, { method: 'DELETE' })
      onChanged(`用户 ${user.username} 已停用。`)
    } catch (caught) {
      onError(errorMessage(caught))
    }
  }

  return (
    <tr>
      <td><strong>{user.username}</strong><small className="cell-subtitle">{user.email || `用户 #${user.id}`}</small></td>
      <td><select aria-label={`${user.username} 的角色`} value={role} onChange={(event) => setRole(event.target.value as Role)}><option value="admin">管理员</option><option value="user">用户</option><option value="viewer">只读</option></select></td>
      <td><label className="switch-label"><input type="checkbox" checked={active} onChange={(event) => setActive(event.target.checked)} />{active ? '启用' : '停用'}</label></td>
      <td>{formatDate(user.created_at)}</td>
      <td className="actions-cell"><button className="button button-secondary" disabled={!dirty || saving} onClick={() => void save()}>{saving ? '保存中…' : '保存'}</button><button className="button button-danger" onClick={() => void remove()}>停用</button></td>
    </tr>
  )
}
