"use client"

import * as React from "react"
import {
  Activity,
  Ban,
  Clock3,
  RefreshCcw,
  ShieldCheck,
  Zap,
  AlertTriangle,
  CircleDot,
} from "lucide-react"
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Area,
  AreaChart,
} from "recharts"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type SecurityEvent = {
  id: string
  timestamp: string
  ip?: string
  path?: string
  method?: string
  prediction?: string
  action?: "ALLOW" | "ALERT" | "RATE_LIMIT" | "BLOCK" | "ERROR"
  confidence?: number | null
  policyReason?: string
  retryAfterSeconds?: number | null
  sequenceLength?: number
  failedAuthCount?: number
  tokenReuseRatio?: number
  status4xxRatio?: number
  status5xxRatio?: number
}

type SecuritySummary = {
  totalEvents: number
  actionCounts: Record<string, number>
  predictionCounts: Record<string, number>
  activeSources: number
  blockedSources: number
  rateLimitedSources: number
  alertSources: number
  recentEvents: SecurityEvent[]
  updatedAt: string
}

const API_BASE = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:3001"

const emptySummary: SecuritySummary = {
  totalEvents: 0,
  actionCounts: { ALLOW: 0, ALERT: 0, RATE_LIMIT: 0, BLOCK: 0, ERROR: 0 },
  predictionCounts: {},
  activeSources: 0,
  blockedSources: 0,
  rateLimitedSources: 0,
  alertSources: 0,
  recentEvents: [],
  updatedAt: new Date().toISOString(),
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

const ACTION_COLORS: Record<string, string> = {
  ALLOW: "#22c55e",
  ALERT: "#f59e0b",
  RATE_LIMIT: "#3b82f6",
  BLOCK: "#ef4444",
  ERROR: "#a855f7",
}

const PREDICTION_COLORS: Record<string, string> = {
  normal: "#22c55e",
  bruteforce: "#ef4444",
  flood: "#f59e0b",
  token_abuse: "#a855f7",
  blocked_source: "#6b7280",
  rate_limited_source: "#3b82f6",
  ml_service_error: "#6b7280",
}

function formatTime(value?: string) {
  if (!value) return "--"
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

function pct(value?: number | null) {
  if (value === null || value === undefined) return "--"
  return `${Math.round(value * 100)}%`
}

function getActionChartData(summary: SecuritySummary) {
  return ["ALLOW", "ALERT", "RATE_LIMIT", "BLOCK"].map((a) => ({
    action: a,
    count: summary.actionCounts?.[a] || 0,
  }))
}

function getPredictionChartData(summary: SecuritySummary) {
  const entries = Object.entries(summary.predictionCounts || {}).filter(
    ([k]) => !["blocked_source", "rate_limited_source", "ml_service_error", "unknown"].includes(k)
  )
  if (entries.length === 0) return [{ name: "Waiting", value: 0 }]
  return entries.map(([name, value]) => ({ name, value }))
}

function getTimelineData(events: SecurityEvent[]) {
  const ordered = [...events].reverse().slice(-30)
  return ordered.map((event, i) => ({
    label: `${i + 1}`,
    risk:
      event.action === "BLOCK" ? 4
        : event.action === "RATE_LIMIT" ? 3
          : event.action === "ALERT" ? 2
            : event.action === "ERROR" ? 3
              : 1,
    confidence: Math.round((event.confidence || 0) * 100),
  }))
}

function actionBadgeClass(action?: string) {
  switch (action) {
    case "BLOCK": return "bg-red-500/15 text-red-400 border-red-500/30"
    case "RATE_LIMIT": return "bg-blue-500/15 text-blue-400 border-blue-500/30"
    case "ALERT": return "bg-amber-500/15 text-amber-400 border-amber-500/30"
    case "ERROR": return "bg-purple-500/15 text-purple-400 border-purple-500/30"
    default: return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
  }
}

/* ------------------------------------------------------------------ */
/*  Custom tooltip                                                     */
/* ------------------------------------------------------------------ */

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-white/10 bg-[#1a1a2e] px-3 py-2 shadow-xl">
      <p className="text-xs text-slate-400">{label}</p>
      {payload.map((p: any, i: number) => (
        <p key={i} className="text-sm font-semibold" style={{ color: p.color || "#e2e8f0" }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Main Dashboard                                                     */
/* ------------------------------------------------------------------ */

export default function SecurityDashboardPage() {
  const [summary, setSummary] = React.useState<SecuritySummary>(emptySummary)
  const [isLoading, setIsLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [isLive, setIsLive] = React.useState(true)

  const loadSummary = React.useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/security/summary`, { cache: "no-store" })
      if (!res.ok) throw new Error(`Backend returned ${res.status}`)
      const payload = await res.json()
      setSummary(payload.summary || emptySummary)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to reach backend")
    } finally {
      setIsLoading(false)
    }
  }, [])

  React.useEffect(() => {
    loadSummary()
    if (!isLive) return
    const id = window.setInterval(loadSummary, 2000)
    return () => window.clearInterval(id)
  }, [loadSummary, isLive])

  async function resetSecurityState() {
    await fetch(`${API_BASE}/api/security/reset`, { method: "POST" })
    await loadSummary()
  }

  const actionChartData = getActionChartData(summary)
  const predictionChartData = getPredictionChartData(summary)
  const timelineData = getTimelineData(summary.recentEvents || [])
  const lastEvent = summary.recentEvents?.[0]

  return (
    <main className="min-h-screen bg-[#0a0a14] text-slate-100">
      {/* ── Top Bar ── */}
      <header className="sticky top-0 z-50 border-b border-white/[0.06] bg-[#0a0a14]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between px-5 py-3">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600">
              <ShieldCheck className="h-4 w-4 text-white" />
            </div>
            <h1 className="text-base font-semibold tracking-tight">API Threat Detection</h1>
            <div className="flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1">
              <CircleDot className={`h-3 w-3 ${error ? "text-red-400" : "text-emerald-400"} ${!error && isLive ? "animate-pulse" : ""}`} />
              <span className="text-[11px] font-medium text-slate-400">
                {error ? "Disconnected" : isLive ? "Live" : "Paused"}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={() => setIsLive(!isLive)}
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-3 text-xs text-slate-300 hover:bg-white/[0.08] hover:text-white"
            >
              <Zap className={`h-3.5 w-3.5 ${isLive ? "text-emerald-400" : "text-slate-500"}`} />
              {isLive ? "Live" : "Paused"}
            </Button>
            <Button
              onClick={loadSummary}
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-3 text-xs text-slate-300 hover:bg-white/[0.08] hover:text-white"
            >
              <RefreshCcw className="h-3.5 w-3.5" /> Refresh
            </Button>
            <Button
              onClick={resetSecurityState}
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 rounded-lg border border-red-500/20 bg-red-500/10 px-3 text-xs text-red-400 hover:bg-red-500/20 hover:text-red-300"
            >
              Reset
            </Button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1600px] space-y-4 p-5">
        {/* ── Error Banner ── */}
        {error && (
          <div className="flex items-center gap-3 rounded-xl border border-amber-500/20 bg-amber-500/[0.06] px-4 py-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <p className="text-sm text-amber-300/90">
              Backend unavailable — start backend (port 3001) and ML service (port 8001). <span className="text-amber-500/70">{error}</span>
            </p>
          </div>
        )}

        {/* ── Stat Cards ── */}
        <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatCard icon={<Activity className="h-4 w-4" />} label="Total Events" value={summary.totalEvents} accent="cyan" />
          <StatCard icon={<Ban className="h-4 w-4" />} label="Blocked" value={summary.actionCounts?.BLOCK || 0} accent="red" />
          <StatCard icon={<Clock3 className="h-4 w-4" />} label="Rate Limited" value={summary.actionCounts?.RATE_LIMIT || 0} accent="blue" />
          <StatCard icon={<ShieldCheck className="h-4 w-4" />} label="Sources" value={summary.activeSources} sub={`${summary.blockedSources} blocked · ${summary.alertSources} alerted`} accent="emerald" />
        </section>

        {/* ── Charts Row ── */}
        <section className="grid gap-3 lg:grid-cols-[1.2fr_0.8fr]">
          {/* Response Distribution */}
          <div className="rounded-xl border border-white/[0.06] bg-[#11111b] p-4">
            <h3 className="mb-1 text-sm font-semibold text-slate-200">Response Distribution</h3>
            <p className="mb-4 text-xs text-slate-500">Actions applied to live requests</p>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={actionChartData} barCategoryGap="24%">
                  <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="action" tickLine={false} axisLine={false} tick={{ fill: "#94a3b8", fontSize: 11 }} />
                  <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: "#64748b", fontSize: 11 }} width={32} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {actionChartData.map((e) => (
                      <Cell key={e.action} fill={ACTION_COLORS[e.action]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Prediction Mix */}
          <div className="rounded-xl border border-white/[0.06] bg-[#11111b] p-4">
            <h3 className="mb-1 text-sm font-semibold text-slate-200">Prediction Mix</h3>
            <p className="mb-4 text-xs text-slate-500">ML class distribution</p>
            <div className="space-y-2.5">
              {predictionChartData.map((item) => {
                const maxVal = Math.max(1, summary.totalEvents)
                const widthPct = Math.min(100, (item.value / maxVal) * 100)
                const color = PREDICTION_COLORS[item.name] || "#64748b"
                return (
                  <div key={item.name}>
                    <div className="mb-1 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                        <span className="text-xs font-medium capitalize text-slate-300">{item.name.replaceAll("_", " ")}</span>
                      </div>
                      <span className="text-xs tabular-nums text-slate-500">{item.value}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${widthPct}%`, backgroundColor: color }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </section>

        {/* ── Risk Timeline + Latest Event ── */}
        <section className="grid gap-3 lg:grid-cols-[1fr_1fr]">
          {/* Risk Timeline */}
          <div className="rounded-xl border border-white/[0.06] bg-[#11111b] p-4">
            <h3 className="mb-1 text-sm font-semibold text-slate-200">Risk Timeline</h3>
            <p className="mb-4 text-xs text-slate-500">Severity of last {timelineData.length || 0} decisions</p>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fill: "#64748b", fontSize: 10 }} />
                  <YAxis domain={[0, 4]} tickLine={false} axisLine={false} tick={{ fill: "#64748b", fontSize: 10 }} width={24} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area dataKey="risk" type="monotone" stroke="#3b82f6" strokeWidth={2} fill="url(#riskGrad)" dot={{ r: 2, fill: "#3b82f6" }} activeDot={{ r: 4, strokeWidth: 0 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Latest Event */}
          <div className="rounded-xl border border-white/[0.06] bg-[#11111b] p-4">
            <h3 className="mb-1 text-sm font-semibold text-slate-200">Latest Event</h3>
            <p className="mb-4 text-xs text-slate-500">Most recent middleware decision</p>
            {lastEvent ? (
              <div className="grid grid-cols-2 gap-2.5">
                <DetailCell label="Action" value={lastEvent.action || "--"} color={ACTION_COLORS[lastEvent.action || ""]} />
                <DetailCell label="Prediction" value={(lastEvent.prediction || "--").replaceAll("_", " ")} />
                <DetailCell label="Confidence" value={pct(lastEvent.confidence)} />
                <DetailCell label="Policy" value={lastEvent.policyReason || "--"} />
                <DetailCell label="Endpoint" value={`${lastEvent.method || ""} ${lastEvent.path || ""}`} />
                <DetailCell label="Seq. Length" value={lastEvent.sequenceLength ?? "--"} />
                <DetailCell label="Auth Fails" value={lastEvent.failedAuthCount ?? "--"} />
                <DetailCell label="Token Reuse" value={pct(lastEvent.tokenReuseRatio)} />
              </div>
            ) : (
              <div className="flex h-40 items-center justify-center rounded-lg border border-dashed border-white/10 text-sm text-slate-600">
                No events yet — run a simulator
              </div>
            )}
          </div>
        </section>

        {/* ── Events Table ── */}
        <section className="rounded-xl border border-white/[0.06] bg-[#11111b]">
          <div className="border-b border-white/[0.06] px-4 py-3">
            <h3 className="text-sm font-semibold text-slate-200">Recent Events</h3>
            <p className="text-xs text-slate-500">Auto-refreshes every 2s while live</p>
          </div>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-white/[0.06] hover:bg-transparent">
                  <TableHead className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Time</TableHead>
                  <TableHead className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Endpoint</TableHead>
                  <TableHead className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Prediction</TableHead>
                  <TableHead className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Action</TableHead>
                  <TableHead className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Confidence</TableHead>
                  <TableHead className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Seq.</TableHead>
                  <TableHead className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Policy</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(summary.recentEvents || []).map((event) => (
                  <TableRow key={event.id} className="border-white/[0.04] hover:bg-white/[0.02]">
                    <TableCell className="font-mono text-[11px] text-slate-400">{formatTime(event.timestamp)}</TableCell>
                    <TableCell className="text-xs text-slate-300">{event.method} {event.path}</TableCell>
                    <TableCell className="text-xs capitalize text-slate-300">{(event.prediction || "--").replaceAll("_", " ")}</TableCell>
                    <TableCell>
                      <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium ${actionBadgeClass(event.action)}`}>
                        {event.action || "--"}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums text-slate-400">{pct(event.confidence)}</TableCell>
                    <TableCell className="text-xs tabular-nums text-slate-400">{event.sequenceLength ?? "--"}</TableCell>
                    <TableCell className="max-w-[180px] truncate text-xs text-slate-500">{event.policyReason || "--"}</TableCell>
                  </TableRow>
                ))}
                {summary.recentEvents.length === 0 && (
                  <TableRow className="border-white/[0.04]">
                    <TableCell colSpan={7} className="h-20 text-center text-sm text-slate-600">
                      {isLoading ? "Loading..." : "No events recorded yet"}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </section>
      </div>
    </main>
  )
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */

function StatCard({
  icon,
  label,
  value,
  sub,
  accent = "cyan",
}: {
  icon: React.ReactNode
  label: string
  value: number
  sub?: string
  accent?: "cyan" | "red" | "blue" | "emerald"
}) {
  const accentMap = {
    cyan: { bg: "bg-cyan-500/10", text: "text-cyan-400", glow: "shadow-cyan-500/5" },
    red: { bg: "bg-red-500/10", text: "text-red-400", glow: "shadow-red-500/5" },
    blue: { bg: "bg-blue-500/10", text: "text-blue-400", glow: "shadow-blue-500/5" },
    emerald: { bg: "bg-emerald-500/10", text: "text-emerald-400", glow: "shadow-emerald-500/5" },
  }
  const a = accentMap[accent]

  return (
    <div className={`group relative overflow-hidden rounded-xl border border-white/[0.06] bg-[#11111b] p-3.5 transition-colors hover:border-white/[0.1] ${a.glow}`}>
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{label}</span>
        <div className={`rounded-lg p-1.5 ${a.bg}`}>
          <span className={a.text}>{icon}</span>
        </div>
      </div>
      <div className="mt-1 text-2xl font-bold tabular-nums tracking-tight text-white">{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-slate-500">{sub}</div>}
    </div>
  )
}

function DetailCell({
  label,
  value,
  color,
}: {
  label: string
  value: React.ReactNode
  color?: string
}) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-0.5 text-sm font-medium capitalize text-slate-200" style={color ? { color } : undefined}>
        {value}
      </div>
    </div>
  )
}
