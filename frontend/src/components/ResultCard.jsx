import SeverityBadge from './SeverityBadge'

const ACTION_LABEL = { pass: 'Passed through', sanitize: 'Sanitized', block: 'Blocked' }

export default function ResultCard({ result }) {
  if (!result) {
    return (
      <div style={styles.empty}>
        <div style={styles.emptyGlyph}>◌</div>
        <div style={styles.emptyText}>Run a prompt through the gateway to see the inspection result here.</div>
      </div>
    )
  }

  const { tier, score, action } = result
  const pct = Math.round(score * 100)

  return (
    <div style={styles.wrap}>
      <div style={styles.header}>
        <SeverityBadge tier={tier} />
        <span style={styles.action}>{ACTION_LABEL[action]}</span>
      </div>

      <div style={styles.meterTrack}>
        <div
          style={{
            ...styles.meterFill,
            width: `${pct}%`,
            background: `var(--tier-${tier.toLowerCase()})`,
          }}
        />
      </div>
      <div style={styles.meterLabel}>
        <span className="mono">{pct}</span> / 100 risk score
      </div>
    </div>
  )
}

const styles = {
  empty: {
    border: '1px dashed var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: '40px 20px',
    textAlign: 'center',
  },
  emptyGlyph: { fontSize: 28, color: 'var(--text-dim)', marginBottom: 8 },
  emptyText: { color: 'var(--text-muted)', fontSize: 13.5, maxWidth: 320, margin: '0 auto' },
  wrap: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 20,
  },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 },
  action: { fontSize: 13, color: 'var(--text-muted)', fontWeight: 500 },
  meterTrack: {
    height: 8,
    background: 'var(--bg)',
    borderRadius: 999,
    overflow: 'hidden',
    border: '1px solid var(--border-soft)',
  },
  meterFill: { height: '100%', borderRadius: 999, transition: 'width 0.4s ease' },
  meterLabel: { marginTop: 8, fontSize: 12, color: 'var(--text-muted)' },
}
