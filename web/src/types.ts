export type Role = 'admin' | 'user' | 'viewer'

export interface SessionUser {
  id: number
  role: Role
}

export interface HealthResponse {
  status: string
  db: string
}

export interface Device {
  device_id: string
  owner_user_id: number | null
  group_id: number | null
  alias: string | null
  hostname: string | null
  os: string | null
  note: string | null
  status: 'online' | 'offline' | 'inactive'
  generation: string
  tags: string[]
  last_seen: string
  created_at: string
  updated_at: string
}

export interface DeviceListResponse {
  items: Device[]
  page: number
  page_size: number
  total: number
}

export interface UserSummary {
  id: number
  username: string
  email: string | null
  role: Role
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface UserListResponse {
  items: UserSummary[]
  total: number
}

export interface LicenseStatus {
  active: boolean
  issued_to: string | null
  max_devices: number | null
  max_users: number | null
  features: number | null
  issued_at: number | null
  expires_at: number | null
  days_remaining: number | null
}

export interface LicenseUsage {
  max_devices: number
  current_devices: number
  online_devices: number
  offline_devices: number
  inactive_devices: number
  max_users: number
  current_users: number
  expires_at: number | null
  days_remaining: number | null
  device_usage_pct: number
  user_usage_pct: number
}

export interface AuditLogItem {
  id: number
  user_id: number | null
  action: string
  target_type: string | null
  target_id: string | null
  detail: unknown
  ip_address: string | null
  created_at: string
}

export interface AuditLogResponse {
  items: AuditLogItem[]
  total: number
  page: number
  page_size: number
}

export interface SecurityPolicy {
  password_min_length: number
  password_require_number: boolean
  password_require_symbol: boolean
  login_max_failures: number
  login_lock_minutes: number
  session_timeout_minutes: number
  allowed_admin_cidrs: string[]
  audit_retention_days: number
}
