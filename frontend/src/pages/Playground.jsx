import { useState } from 'react'
import PromptInput from '../components/PromptInput'
import ResultCard from '../components/ResultCard'
import ReasonCard from '../components/ReasonCard'
import { api } from '../api'

export default function Playground() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleAnalyze = async (prompt, source) => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.detect(prompt, 'playground-session', source)
      setResult(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Live Attack Simulator"
        title="Playground"
        subtitle="Type any message and watch it move through all six detection layers in real time."
      />

      <div style={styles.grid}>
        <div style={styles.col}>
          <PromptInput onAnalyze={handleAnalyze} loading={loading} />
          {error && <div style={styles.error}>{error}</div>}
          <div style={{ marginTop: 16 }}>
            <ResultCard result={result} />
          </div>
        </div>
        <div style={styles.col}>
          {result ? (
            <ReasonCard result={result} />
          ) : (
            <div style={styles.hint}>
              <div style={styles.hintTitle}>How this gets decided</div>
              <ol style={styles.hintList}>
                <li>Rule/pattern layer scans for known injection phrasing.</li>
                <li>SBERT embedding compares it to known attack + benign clusters.</li>
                <li>A lightweight classifier scores malicious probability.</li>
                <li>An agreement gate requires 2+ corroborating signals before a HIGH block — so a lone trigger word never gets you flagged.</li>
              </ol>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export function PageHeader({ eyebrow, title, subtitle }) {
  return (
    <div style={styles.header}>
      {eyebrow && <div style={styles.eyebrow}>{eyebrow}</div>}
      <h1 style={styles.title}>{title}</h1>
      {subtitle && <p style={styles.subtitle}>{subtitle}</p>}
    </div>
  )
}

const styles = {
  header: { marginBottom: 28 },
  eyebrow: {
    fontFamily: 'var(--font-mono)',
    fontSize: 11.5,
    color: 'var(--signal)',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    marginBottom: 6,
  },
  title: { fontSize: 28, fontWeight: 800, margin: 0, letterSpacing: '-0.02em' },
  subtitle: { color: 'var(--text-muted)', fontSize: 14.5, marginTop: 8, maxWidth: 560, lineHeight: 1.5 },
  grid: { display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: 24, alignItems: 'start' },
  col: { display: 'flex', flexDirection: 'column' },
  error: {
    marginTop: 12,
    color: 'var(--tier-high)',
    background: 'var(--tier-high-bg)',
    padding: '10px 14px',
    borderRadius: 'var(--radius-sm)',
    fontSize: 13,
  },
  hint: {
    border: '1px dashed var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 20,
  },
  hintTitle: { fontSize: 13, fontWeight: 700, marginBottom: 12, color: 'var(--text-primary)' },
  hintList: { margin: 0, paddingLeft: 18, color: 'var(--text-muted)', fontSize: 13.5, lineHeight: 1.9 },
}
