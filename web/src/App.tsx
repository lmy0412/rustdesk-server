import { Navigate, Route, Routes, useLocation } from 'react-router'
import { useAuth } from './auth/AuthContext'
import { Layout } from './components/Layout'
import { Loading } from './components/Ui'
import { AuditLogsPage } from './pages/AuditLogsPage'
import { DashboardPage } from './pages/DashboardPage'
import { DevicesPage } from './pages/DevicesPage'
import { LicensePage } from './pages/LicensePage'
import { LoginPage } from './pages/LoginPage'
import { SettingsPage } from './pages/SettingsPage'
import { UsersPage } from './pages/UsersPage'

function RequireAuth({ admin = false, children }: { admin?: boolean; children: React.ReactNode }) {
  const { initializing, user } = useAuth()
  const location = useLocation()
  if (initializing) return <div className="center-screen"><Loading label="正在恢复会话" /></div>
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  if (admin && user.role !== 'admin') return <Navigate to="/dashboard" replace />
  return children
}

function HomeRedirect() {
  const { initializing, user } = useAuth()
  if (initializing) return <div className="center-screen"><Loading label="正在恢复会话" /></div>
  return <Navigate to={user ? '/dashboard' : '/login'} replace />
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/license" element={<LicensePage />} />
        <Route path="/users" element={<RequireAuth admin><UsersPage /></RequireAuth>} />
        <Route path="/audit-logs" element={<RequireAuth admin><AuditLogsPage /></RequireAuth>} />
        <Route path="/settings" element={<RequireAuth admin><SettingsPage /></RequireAuth>} />
      </Route>
      <Route path="/" element={<HomeRedirect />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
