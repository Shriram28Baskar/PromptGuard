export default function ReasonCard({ result }) {
  if (!result) return null
  const { tier, score, action, explanation, sanitized_output, details } = result

  return (
    <div style={styles.wrap}>
      <div style={styles.reasonText}>{explanation}</div>

      {sanitized_output && (
        <div style={styles.sanitizedBox}>
          <div style={styles.sanitizedLabel}>Sanitized output (spotlighting / quarantine)</div>
          <pre style={styles.sanitizedPre}>{sanitized_output}</pre>
        </div>
      )}

      <div style={styles.grid}>
        <Metric label="Risk score" value={score.toFixed(2)} />
        <Metric label="Rule score" value={details.rule_score.toFixed(2)} />
        <Metric label="Embedding sim." value={details.embedding_score.toFixed(2)} />
        <Metric label="Classifier prob." value={details.classifier_prob.toFixed(2)} />
        <Metric label="Drift score" value={details.drift_score.toFixed(2)} />
        <Metric label="Benign similarity" value={details.benign_similarity.toFixed(2)} />
      </div>

      {details.matched_rules?.length > 0 && (
        <div style={styles.section}>
          <div style={styles.sectionLabel}>Matched patterns</div>
          <div style={styles.chipRow}>
            {details.matched_rules.map((r) => (
              <span key={r} style={styles.chip}>{r}</span>
            ))}
          </div>
        </div>
      )}

      {details.nearest_attack_cluster && (
        <div style={styles.section}>
          <div style={styles.sectionLabel}>Nearest known attack cluster</div>
          <div style={styles.monoLine}>{details.nearest_attack_cluster}</div>
        </div>
      )}

      {details.drift_flagged && (
        <div style={styles.driftWarning}>
          ⚠ Session intent has drifted across recent turns — flagged independent of this single message.
        </div>
      )}
    </div>
  )
}

function Metric({ label, value }) {
  return (
    <div style={styles.metric}>
      <div style={styles.metricValue}>{value}</div>
      <div style={styles.metricLabel}>{label}</div>
    </div>
  )
}

const styles = {
  wrap: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 20,
  },
  reasonText: {
    fontSize: 14.5,
    lineHeight: 1.6,
    color: 'var(--text-primary)',
    marginBottom: 18,
  },
  sanitizedBox: {
    background: 'var(--bg)',
    border: '1px dashed var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: 12,
    marginBottom: 18,
  },
  sanitizedLabel: {
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: 'var(--text-dim)',
    marginBottom: 8,
    fontFamily: 'var(--font-mono)',
  },
  sanitizedPre: {
    fontFamily: 'var(--font-mono)',
    fontSize: 12.5,
    color: 'var(--signal)',
    whiteSpace: 'pre-wrap',
    margin: 0,
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: 12,
    marginBottom: 8,
  },
  metric: {
    background: 'var(--bg)',
    border: '1px solid var(--border-soft)',
    borderRadius: 'var(--radius-sm)',
    padding: '10px 12px',
  },
  metricValue: {
    fontFamily: 'var(--font-mono)',
    fontSize: 18,
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  metricLabel: {
    fontSize: 11,
    color: 'var(--text-dim)',
    marginTop: 2,
  },
  section: { marginTop: 16 },
  sectionLabel: {
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: 'var(--text-dim)',
    marginBottom: 8,
    fontFamily: 'var(--font-mono)',
  },
  chipRow: { display: 'flex', gap: 6, flexWrap: 'wrap' },
  chip: {
    background: 'var(--tier-high-bg)',
    color: 'var(--tier-high)',
    fontFamily: 'var(--font-mono)',
    fontSize: 11.5,
    padding: '4px 10px',
    borderRadius: 999,
  },
  monoLine: { fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)' },
  driftWarning: {
    marginTop: 16,
    fontSize: 12.5,
    color: 'var(--tier-medium)',
    background: 'var(--tier-medium-bg)',
    padding: '10px 12px',
    borderRadius: 'var(--radius-sm)',
  },
}
