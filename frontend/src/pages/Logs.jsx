import { useEffect, useState } from 'react'
import { PageHeader } from './Playground'
import HistoryTable from '../components/HistoryTable'
import { api } from '../api'

const TIERS = ['ALL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']

export default function Logs() {
  const [logs, setLogs] = useState([])
  const [tier, setTier] = useState('ALL')
  const [loading, setLoading] = useState(false)

  const load = async (t) => {
    setLoading(true)
    try {
      const res = await api.getLogs(t === 'ALL' ? null : t)
      setLogs(res.logs)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load(tier) }, [tier])

  return (
    <div>
      <PageHeader eyebrow="Audit Trail" title="Logs" subtitle="Every inspected message, filterable by severity tier." />

      <div style={styles.toolbar}>
        <div style={styles.filters}>
          {TIERS.map((t) => (
            <button
              key={t}
              onClick={() => setTier(t)}
              style={{ ...styles.filterBtn, ...(tier === t ? styles.filterBtnActive : {}) }}
            >
              {t}
            </button>
          ))}
        </div>
        <button style={styles.refreshBtn} onClick={() => load(tier)} disabled={loading}>
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      <HistoryTable logs={logs} />
    </div>
  )
}

const styles = {
  toolbar: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 },
  filters: { display: 'flex', gap: 6 },
  filterBtn: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
    fontSize: 11.5,
    padding: '7px 14px',
    borderRadius: 999,
  },
  filterBtnActive: { background: 'var(--signal-dim)', color: 'var(--signal)', borderColor: 'var(--signal)' },
  refreshBtn: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 12.5,
    padding: '8px 16px',
    borderRadius: 'var(--radius-sm)',
  },
}
