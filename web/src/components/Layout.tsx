import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router'
import { useAuth } from '../auth/AuthContext'

const mainLinks = [
  { to: '/dashboard', label: '仪表盘', mark: 'D' },
  { to: '/devices', label: '设备管理', mark: 'M' },
  { to: '/license', label: '许可证', mark: 'L' },
]

const adminLinks = [
  { to: '/users', label: '用户管理', mark: 'U' },
  { to: '/audit-logs', label: '审计日志', mark: 'A' },
  { to: '/settings', label: '系统设置', mark: 'S' },
]

export function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const links = user?.role === 'admin' ? [...mainLinks, ...adminLinks] : mainLinks

  async function handleLogout() {
    try {
      await logout()
    } finally {
      navigate('/login', { replace: true })
    }
  }

  return (
    <div className="app-shell">
      <button className="mobile-menu" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        菜单
      </button>
      <aside className={`sidebar ${open ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <span className="brand-mark">R</span>
          <div>
            <strong>RustDesk</strong>
            <small>Server Console</small>
          </div>
        </div>
        <nav className="nav-list" aria-label="主导航">
          {links.map((link) => (
            <NavLink key={link.to} to={link.to} onClick={() => setOpen(false)}>
              <span>{link.mark}</span>
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="identity">
            <span>{user?.role === 'admin' ? '管理员' : user?.role === 'viewer' ? '只读用户' : '用户'}</span>
            <small>用户 #{user?.id}</small>
          </div>
          <button className="button button-quiet button-block" onClick={() => void handleLogout()}>
            退出登录
          </button>
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
