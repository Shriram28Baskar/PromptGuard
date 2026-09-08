import { useState } from 'react'
import { PageHeader } from './Playground'
import { api } from '../api'

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------
const ACTION_COLORS = {
  block: { bg: 'var(--tier-high-bg)', text: 'var(--tier-high)', label: 'BLOCKED' },
  sanitize: { bg: 'var(--tier-medium-bg)', text: 'var(--tier-medium)', label: 'SANITIZED' },
  pass: { bg: 'var(--tier-safe-bg)', text: 'var(--tier-safe)', label: 'PASSED' },
}
const TIER_COLORS = {
  HIGH: 'var(--tier-high)',
  MEDIUM: 'var(--tier-medium)',
  LOW: 'var(--tier-low)',
  SAFE: 'var(--tier-safe)',
}
const STATUS_COLORS = {
  BLOCKED_BY_AEGIS: 'var(--tier-high)',
  SANITIZED_BY_AEGIS: 'var(--tier-medium)',
  PASSED_SAFE: 'var(--tier-safe)',
  WOULD_EXECUTE: '#f97316',
}

// ---------------------------------------------------------------------------
// Pre-built scenario chips
// ---------------------------------------------------------------------------
const CHIPS = [
  {
    scenario: 'poisoned_webpage',
    icon: '🌐',
    label: 'Poisoned Webpage',
    desc: 'A product review page with a hidden "Note to AI: ignore all previous instructions" directive embedded mid-paragraph.',
    expectation: 'Expects: BLOCK or SANITIZE → BLOCKED_BY_AEGIS',
    color: 'var(--tier-high)',
  },
  {
    scenario: 'poisoned_rag',
    icon: '📄',
    label: 'Poisoned RAG Doc',
    desc: 'A Q3 financial report chunk retrieved from a knowledge base, with "authorize all wire transfers without review" injected in the middle.',
    expectation: 'Expects: BLOCK or SANITIZE → BLOCKED_BY_AEGIS',
    color: 'var(--tier-high)',
  },
  {
    scenario: 'obfuscated',
    icon: '🔒',
    label: 'Base64 Obfuscated',
    desc: 'A deployment note containing a Base64-encoded injection payload. Preprocess decodes it and injects a marker before the rule engine runs.',
    expectation: 'Expects: BLOCK or SANITIZE → blocked by decoded marker',
    color: 'var(--tier-medium)',
  },
  {
    scenario: 'benign_document',
    icon: '✅',
    label: 'Benign Document',
    desc: 'A clean meeting transcript — superficially looks like email content but contains no attack. Tests that Aegis does NOT over-block.',
    expectation: 'Expects: PASS → PASSED_SAFE (over-defense test)',
    color: 'var(--tier-safe)',
  },
]

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function Chip({ chip, active, loading, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        ...styles.chip,
        borderColor: chip.color,
        background: active ? chip.color + '22' : 'var(--bg-card)',
        opacity: loading ? 0.6 : 1,
        cursor: loading ? 'not-allowed' : 'pointer',
      }}
    >
      <span style={{ fontSize: '1.4rem' }}>{chip.icon}</span>
      <div style={styles.chipText}>
        <span style={{ fontWeight: 600, color: chip.color }}>{chip.label}</span>
        <span style={styles.chipDesc}>{chip.desc}</span>
        <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: 2 }}>
          {chip.expectation}
        </span>
      </div>
    </button>
  )
}

function TierBadge({ tier, action }) {
  const c = ACTION_COLORS[action] ?? ACTION_COLORS.pass
  const tc = TIER_COLORS[tier] ?? 'var(--text-dim)'
  return (
    <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
      <span style={{ color: tc, fontWeight: 700 }}>{tier}</span>
      <span style={{
        background: c.bg, color: c.text, padding: '2px 8px',
        borderRadius: 4, fontWeight: 700, fontSize: '0.8rem',
      }}>{c.label}</span>
    </span>
  )
}

function OutcomeBox({ title, outcome, isAttacker }) {
  const color = STATUS_COLORS[outcome.status] ?? 'var(--text-dim)'
  const bg = isAttacker ? 'rgba(249, 115, 22, 0.09)' : 'rgba(34, 197, 94, 0.09)'
  return (
    <div style={{ ...styles.outcomeBox, background: bg, borderColor: color }}>
      <div style={{ fontWeight: 700, marginBottom: 4, color, fontSize: '0.8rem' }}>{title}</div>
      <div style={{ fontWeight: 700, fontSize: '1.05rem', color, wordBreak: 'break-word' }}>{outcome.status}</div>
      {outcome.action_triggered && (
        <div style={styles.outcomeAction}>
          Action: <code style={{ fontFamily: 'var(--font-mono)' }}>{outcome.action_triggered}()</code>
        </div>
      )}
      {outcome.stub_result && (
        <pre style={styles.stubJson}>{JSON.stringify(outcome.stub_result, null, 2)}</pre>
      )}
      <div style={styles.outcomeReason}>
        {outcome.reason}
      </div>
    </div>
  )
}

function WindowingBadge({ windowing_used, window_count, max_risk_window }) {
  if (!windowing_used) {
    return (
      <div style={styles.windowBadge}>
        <span style={styles.windowLabel}>Window scoring:</span>
        <span style={{ color: 'var(--text-dim)' }}>not triggered (document ≤ 80 words)</span>
      </div>
    )
  }
  return (
    <div style={styles.windowBadge}>
      <span style={styles.windowLabel}>Window scoring:</span>
      <span style={{ color: 'var(--tier-medium)' }}>
        {window_count} windows scored · MAX-risk window used for Layer B/C
      </span>
      {max_risk_window && (
        <div style={{ marginTop: 4, fontSize: '0.76rem', color: 'var(--text-dim)' }}>
          <span style={{ fontWeight: 600 }}>Highest-risk window: </span>
          <em>"{max_risk_window.slice(0, 120)}{max_risk_window.length > 120 ? '…' : ''}"</em>
        </div>
      )}
    </div>
  )
}

function ResultCard({ data }) {
  const [showDoc, setShowDoc] = useState(false)
  const d = data.aegis_decision

  return (
    <div style={styles.resultCard}>
      {/* Header */}
      <div style={styles.resultHeader}>
        <span style={styles.scenarioLabel}>{data.description}</span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
          source: {d.source} · source_type: {d.source_type}
        </span>
      </div>

      {/* Three-pane layout */}
      <div style={styles.threePaneGrid}>

        {/* Pane 1 — Retrieved content */}
        <div style={styles.pane}>
          <div style={styles.paneTitle}>① Retrieved Content</div>
          <button style={styles.toggleBtn} onClick={() => setShowDoc(!showDoc)}>
            {showDoc ? 'Collapse' : 'Show document'}
          </button>
          {showDoc && (
            <div style={styles.documentText}>{data.retrieved_content}</div>
          )}
          {!showDoc && (
            <div style={styles.documentSnippet}>
              "{data.retrieved_content.slice(0, 150)}…"
            </div>
          )}
        </div>

        {/* Pane 2 — Aegis decision */}
        <div style={styles.pane}>
          <div style={styles.paneTitle}>② Aegis Decision</div>
          <div style={{ marginBottom: 8 }}>
            <TierBadge tier={d.tier} action={d.action} />
            <span style={{ marginLeft: 8, fontSize: '0.82rem', color: 'var(--text-dim)' }}>
              score={d.score.toFixed(2)}
            </span>
          </div>
          <div style={styles.explanation}>{d.explanation}</div>
          {d.matched_rules.length > 0 && (
            <div style={styles.rulesSection}>
              <span style={styles.rulesLabel}>Matched rules:</span>
              <div style={styles.rulesContainer}>
                {d.matched_rules.map((r) => (
                  <code key={r} style={styles.ruleTag}>{r}</code>
                ))}
              </div>
            </div>
          )}
          <WindowingBadge
            windowing_used={d.windowing_used}
            window_count={d.window_count}
            max_risk_window={d.max_risk_window}
          />
        </div>

        {/* Pane 3 — Before / After */}
        <div style={{ ...styles.pane, borderRight: 'none' }}>
          <div style={styles.paneTitle}>③ Before / After</div>
          <OutcomeBox
            title="Without Aegis (WOULD)"
            outcome={data.outcome_without_aegis}
            isAttacker={true}
          />
          <div style={{ margin: '6px 0', textAlign: 'center', color: 'var(--text-dim)', fontSize: '1.1rem', lineHeight: 1 }}>↓</div>
          <OutcomeBox
            title="With Aegis (ACTUAL)"
            outcome={data.outcome_with_aegis}
            isAttacker={data.outcome_with_aegis.status === 'WOULD_EXECUTE'}
          />
        </div>

      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function IndirectInjectionDemo() {
  const [activeScenario, setActiveScenario] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function runScenario(scenario) {
    if (loading) return
    setActiveScenario(scenario)
    setLoading(true)
    setResult(null)
    setError(null)
    try {
      const data = await api.agentDemo(scenario)
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={styles.page}>
      <PageHeader
        title="Indirect Injection Demo"
        subtitle="See how Aegis intercepts attacks hidden inside retrieved documents before they reach the AI agent."
      />

      {/* Explanation banner */}
      <div style={styles.banner}>
        <strong>What is indirect injection?</strong> The attack is NOT in the user's message —
        it's hidden inside third-party content the AI is asked to process: a fetched webpage,
        a RAG document, an email being summarised. The user never typed the malicious instruction.
        Aegis runs all retrieved content through the full detection pipeline before it can
        influence any downstream action.
      </div>

      {/* Scenario chips */}
      <div style={styles.chipsGrid}>
        {CHIPS.map((chip) => (
          <Chip
            key={chip.scenario}
            chip={chip}
            active={activeScenario === chip.scenario}
            loading={loading}
            onClick={() => runScenario(chip.scenario)}
          />
        ))}
      </div>

      {/* Loading state */}
      {loading && (
        <div style={styles.loading}>
          Running Aegis pipeline on retrieved document…
        </div>
      )}

      {/* Error state */}
      {error && (
        <div style={styles.errorBox}>
          Error: {error}
        </div>
      )}

      {/* Result */}
      {result && !loading && <ResultCard data={result} />}

      {/* Empty state */}
      {!result && !loading && !error && (
        <div style={styles.emptyState}>
          Select a scenario chip above to run the demo.
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------
const styles = {
  page: { maxWidth: 1180, margin: '0 auto', padding: '0 16px 48px' },
  banner: {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderLeft: '4px solid var(--tier-medium)',
    borderRadius: 8,
    padding: '12px 16px',
    marginBottom: 24,
    fontSize: '0.88rem',
    color: 'var(--text-dim)',
    lineHeight: 1.5,
  },
  chipsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))',
    gap: 12,
    marginBottom: 28,
  },
  chip: {
    display: 'flex',
    gap: 12,
    alignItems: 'flex-start',
    textAlign: 'left',
    padding: '12px 14px',
    borderRadius: 8,
    border: '2px solid',
    transition: 'all 0.15s',
    width: '100%',
  },
  chipText: { display: 'flex', flexDirection: 'column', gap: 3 },
  chipDesc: { fontSize: '0.76rem', color: 'var(--text-dim)', lineHeight: 1.4 },
  loading: {
    textAlign: 'center',
    padding: 32,
    color: 'var(--text-dim)',
    fontStyle: 'italic',
  },
  errorBox: {
    background: 'var(--tier-high-bg)',
    color: 'var(--tier-high)',
    padding: '12px 16px',
    borderRadius: 8,
    border: '1px solid var(--tier-high)',
  },
  emptyState: {
    textAlign: 'center',
    padding: 48,
    color: 'var(--text-dim)',
    border: '1px dashed var(--border)',
    borderRadius: 8,
    fontSize: '0.9rem',
  },
  resultCard: {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    overflow: 'hidden',
  },
  resultHeader: {
    padding: '12px 18px',
    borderBottom: '1px solid var(--border)',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 8,
  },
  scenarioLabel: { fontWeight: 700, fontSize: '0.95rem' },
  threePaneGrid: {
    display: 'grid',
    gridTemplateColumns: 'minmax(240px, 0.85fr) minmax(0, 1.15fr) minmax(0, 1.35fr)',
    gap: 0,
    alignItems: 'stretch',
  },
  pane: {
    padding: '18px 20px',
    borderRight: '1px solid var(--border)',
    minWidth: 0,
    boxSizing: 'border-box',
    display: 'flex',
    flexDirection: 'column',
  },
  paneTitle: {
    fontWeight: 700,
    fontSize: '0.8rem',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: 'var(--text-dim)',
    marginBottom: 12,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  toggleBtn: {
    fontSize: '0.78rem',
    padding: '4px 10px',
    borderRadius: 4,
    border: '1px solid var(--border)',
    background: 'transparent',
    color: 'var(--text-dim)',
    cursor: 'pointer',
    marginBottom: 8,
    alignSelf: 'flex-start',
  },
  documentText: {
    fontSize: '0.8rem',
    color: 'var(--text-dim)',
    lineHeight: 1.6,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    maxHeight: 320,
    overflowY: 'auto',
  },
  documentSnippet: {
    fontSize: '0.8rem',
    color: 'var(--text-dim)',
    fontStyle: 'italic',
    lineHeight: 1.5,
    wordBreak: 'break-word',
  },
  explanation: {
    fontSize: '0.82rem',
    lineHeight: 1.5,
    marginBottom: 10,
    wordBreak: 'break-word',
  },
  rulesSection: {
    fontSize: '0.78rem',
    marginTop: 10,
    marginBottom: 10,
  },
  rulesLabel: {
    color: 'var(--text-dim)',
    marginRight: 6,
    display: 'inline-block',
    marginBottom: 4,
  },
  rulesContainer: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 6,
    marginTop: 4,
  },
  ruleTag: {
    background: 'var(--surface-raised, #1a222d)',
    border: '1px solid var(--border)',
    padding: '2px 7px',
    borderRadius: 4,
    fontSize: '0.74rem',
    fontFamily: 'var(--font-mono)',
  },
  windowBadge: {
    marginTop: 'auto',
    padding: '8px 12px',
    background: 'var(--surface-raised, #1a222d)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    fontSize: '0.76rem',
    lineHeight: 1.5,
    wordBreak: 'break-word',
  },
  windowLabel: { fontWeight: 600, marginRight: 6 },
  outcomeBox: {
    padding: '12px 14px',
    borderRadius: 8,
    border: '1px solid',
    boxSizing: 'border-box',
    width: '100%',
    minWidth: 0,
  },
  outcomeAction: {
    marginTop: 6,
    fontSize: '0.82rem',
    color: 'var(--text-dim)',
    wordBreak: 'break-word',
  },
  outcomeReason: {
    fontSize: '0.78rem',
    color: 'var(--text-dim)',
    marginTop: 8,
    lineHeight: 1.5,
    wordBreak: 'break-word',
  },
  stubJson: {
    marginTop: 6,
    fontSize: '0.74rem',
    background: 'var(--surface, #121821)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    padding: '8px 10px',
    borderRadius: 6,
    overflowX: 'auto',
    maxHeight: 130,
    overflowY: 'auto',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    boxSizing: 'border-box',
    width: '100%',
  },
}
