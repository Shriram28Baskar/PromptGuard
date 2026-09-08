import SeverityBadge from './SeverityBadge'

export default function HistoryTable({ logs }) {
  if (!logs || logs.length === 0) {
    return <div style={styles.empty}>No logged requests yet.</div>
  }

  return (
    <div style={styles.wrap}>
      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>Time</th>
            <th style={styles.th}>Severity</th>
            <th style={styles.th}>Prompt</th>
            <th style={styles.th}>Reason</th>
            <th style={styles.th}>Action</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id} style={styles.tr}>
              <td style={styles.tdMono}>{new Date(log.timestamp * 1000).toLocaleTimeString()}</td>
              <td style={styles.td}><SeverityBadge tier={log.tier} /></td>
              <td style={{ ...styles.td, ...styles.promptCell }} title={log.prompt}>{log.prompt}</td>
              <td style={{ ...styles.td, ...styles.reasonCell }} title={log.explanation}>{log.explanation}</td>
              <td style={styles.tdMono}>{log.action}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const styles = {
  empty: {
    padding: 40,
    textAlign: 'center',
    color: 'var(--text-muted)',
    border: '1px dashed var(--border)',
    borderRadius: 'var(--radius-lg)',
  },
  wrap: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    overflow: 'auto',
  },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: {
    textAlign: 'left',
    padding: '12px 16px',
    color: 'var(--text-dim)',
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    borderBottom: '1px solid var(--border)',
    position: 'sticky',
    top: 0,
    background: 'var(--surface)',
  },
  tr: { borderBottom: '1px solid var(--border-soft)' },
  td: { padding: '12px 16px', verticalAlign: 'top', color: 'var(--text-primary)' },
  tdMono: {
    padding: '12px 16px',
    verticalAlign: 'top',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    whiteSpace: 'nowrap',
  },
  promptCell: {
    maxWidth: 260,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    fontFamily: 'var(--font-mono)',
    fontSize: 12.5,
  },
  reasonCell: {
    maxWidth: 340,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    color: 'var(--text-muted)',
  },
}
