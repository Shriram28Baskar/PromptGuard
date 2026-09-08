import { useState } from 'react'
import { PageHeader } from './Playground'
import { api } from '../api'

// ---------------------------------------------------------------------------
// Tier / verdict colour helpers  (mirrors existing ResultCard palette)
// ---------------------------------------------------------------------------
const TIER_COLORS = {
  HIGH: { bg: 'var(--tier-high-bg)', text: 'var(--tier-high)' },
  MEDIUM: { bg: 'var(--tier-medium-bg)', text: 'var(--tier-medium)' },
  LOW: { bg: 'var(--tier-low-bg)', text: 'var(--tier-low)' },
  SAFE: { bg: 'var(--tier-safe-bg)', text: 'var(--tier-safe)' },
}
const verdictColor = (v) => ({
  ALLOW: '#22c55e',
  DENY: 'var(--tier-high)',
  'N/A': 'var(--text-dim)',
}[v] ?? 'var(--text-dim)')

const execColor = (v) => ({
  EXECUTED: '#22c55e',
  NOT_EXECUTED: 'var(--tier-high)',
  'N/A': 'var(--text-dim)',
}[v] ?? 'var(--text-dim)')

// ---------------------------------------------------------------------------
// Demo scenario cards
// ---------------------------------------------------------------------------
const SCENARIOS = [
  {
    key: 'A',
    label: 'Scenario A — Benign',
    desc: 'Legitimate $500 payment request. Expects: PASS → ALLOW → EXECUTE.',
    color: '#22c55e',
  },
  {
    key: 'B',
    label: 'Scenario B — Injection',
    desc: 'Prompt injection attack. Expects: BLOCK → ARGUS NOT REACHED.',
    color: 'var(--tier-high)',
  },
  {
    key: 'C',
    label: 'Scenario C — Indirect Injection',
    desc: 'Malicious instructions embedded in tool/external content. Shows detection-controlled outcome + independent policy.',
    color: 'var(--tier-medium)',
  },
  {
    key: 'D',
    label: 'Scenario D — Over Limit',
    desc: 'Benign prompt, $50 000 action (exceeds $10 000 limit). Expects: PASS → DENY → NOT_EXECUTED.',
    color: '#f59e0b',
  },
]

// ---------------------------------------------------------------------------
// Security flow trace display
// ---------------------------------------------------------------------------
function FlowTrace({ result }) {
  const tierColors = TIER_COLORS[result.security.tier] ?? TIER_COLORS.SAFE
  return (
    <div style={styles.traceCard}>
      {/* Header */}
      <div style={styles.traceHeader}>
        <span style={styles.traceLabel}>Request</span>
        <span style={styles.traceId}>{result.request_id}</span>
      </div>

      {/* Prompt */}
      <div style={styles.section}>
        <div style={styles.sectionLabel}>Prompt</div>
        <div style={styles.promptText}>{result.prompt}</div>
      </div>

      {/* Proposed Action */}
      <div style={styles.section}>
        <div style={styles.sectionLabel}>Proposed Action</div>
        <pre style={styles.pre}>{JSON.stringify(result.proposed_action, null, 2)}</pre>
      </div>

      {/* Gate flow */}
      <div style={styles.gateRow}>
        {/* Gate 1: Schema */}
        <GateBox
          title="Gate 1 — Schema"
          verdict="PASS"
          verdictColor="#22c55e"
          detail="ProposedAction parsed successfully."
        />

        <Arrow />

        {/* Gate 2: Security */}
        <GateBox
          title="Gate 2 — PromptGuard"
          verdict={result.security.tier + (result.security.is_degraded ? ' ⚠ DEGRADED' : '')}
          verdictColor={result.security.is_degraded ? 'var(--tier-high)' : tierColors.text}
          detail={`Action: ${result.security.action.toUpperCase()}  |  Score: ${(result.security.score * 100).toFixed(0)}/100`}
          explanation={result.security.explanation}
          bg={result.security.is_degraded ? 'var(--tier-high-bg)' : tierColors.bg}
        />

        <Arrow />

        {/* Gate 3: Policy */}
        <GateBox
          title="Gate 3 — Policy"
          verdict={result.policy.verdict}
          verdictColor={verdictColor(result.policy.verdict)}
          detail={result.policy.reason}
        />

        <Arrow />

        {/* ARGUS */}
        <GateBox
          title="ARGUS Simulator"
          verdict={result.argus.execution_result}
          verdictColor={execColor(result.argus.execution_result)}
          detail={result.argus.detail}
          highlight={result.argus.argus_reached}
        />
      </div>

      {/* Receipt (if executed) */}
      {result.argus.receipt_id && (
        <div style={styles.receipt}>
          <span style={styles.receiptLabel}>Receipt ID</span>
          <span style={styles.receiptId}>{result.argus.receipt_id}</span>
        </div>
      )}
    </div>
  )
}

function GateBox({ title, verdict, verdictColor: vc, detail, explanation, bg, highlight }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div style={{ ...styles.gateBox, background: bg || 'var(--surface-raised)', outline: highlight ? '1.5px solid #22c55e' : 'none' }}>
      <div style={styles.gateTitle}>{title}</div>
      <div style={{ ...styles.gateVerdict, color: vc }}>{verdict}</div>
      <div style={styles.gateDetail}>{detail}</div>
      {explanation && (
        <button style={styles.expandBtn} onClick={() => setExpanded(e => !e)}>
          {expanded ? '▲ hide' : '▼ explain'}
        </button>
      )}
      {expanded && <div style={styles.explanation}>{explanation}</div>}
    </div>
  )
}

function Arrow() {
  return <div style={styles.arrow}>→</div>
}

// ---------------------------------------------------------------------------
// Manual proposal form
// ---------------------------------------------------------------------------
const DEFAULT_FORM = {
  prompt: '',
  recipient_id: '',
  authorized_by: 'admin',
  amount: '',
  action_type: 'approve_transaction',
  currency: 'USD',
}

function ManualForm({ onResult }) {
  const [form, setForm] = useState(DEFAULT_FORM)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const action = {
        action_type: form.action_type,
        recipient_id: form.recipient_id,
        authorized_by: form.authorized_by,
        currency: form.currency,
        request_id: `manual-${Date.now()}`,
        metadata: {},
      }
      if (form.action_type === 'approve_transaction') {
        const amt = parseFloat(form.amount)
        if (isNaN(amt)) throw new Error('Amount must be a number for approve_transaction.')
        action.amount = amt
      }
      const res = await api.proposeAction(form.prompt, null, action)
      onResult(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      <div style={styles.formTitle}>Manual Proposal</div>

      <label style={styles.label}>Prompt</label>
      <textarea
        style={styles.textarea}
        rows={3}
        value={form.prompt}
        onChange={e => set('prompt', e.target.value)}
        required
        placeholder="Enter the originating prompt text..."
      />

      <label style={styles.label}>Action Type</label>
      <select style={styles.select} value={form.action_type} onChange={e => set('action_type', e.target.value)}>
        <option value="approve_transaction">approve_transaction</option>
        <option value="reject_transaction">reject_transaction</option>
        <option value="authorize_access">authorize_access</option>
      </select>

      {form.action_type === 'approve_transaction' && (
        <>
          <label style={styles.label}>Amount</label>
          <input
            style={styles.input}
            type="number"
            step="0.01"
            value={form.amount}
            onChange={e => set('amount', e.target.value)}
            placeholder="e.g. 500"
            required
          />
          <label style={styles.label}>Currency</label>
          <input
            style={styles.input}
            value={form.currency}
            onChange={e => set('currency', e.target.value)}
            maxLength={3}
          />
        </>
      )}

      <label style={styles.label}>Recipient ID</label>
      <input
        style={styles.input}
        value={form.recipient_id}
        onChange={e => set('recipient_id', e.target.value)}
        required
        placeholder="e.g. alice@example.com"
      />

      <label style={styles.label}>Authorized By</label>
      <input
        style={styles.input}
        value={form.authorized_by}
        onChange={e => set('authorized_by', e.target.value)}
        required
        placeholder="e.g. admin"
      />

      {error && <div style={styles.error}>{error}</div>}

      <button type="submit" style={styles.btn} disabled={loading}>
        {loading ? 'Evaluating…' : '⚡ Propose & Evaluate'}
      </button>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function ArgusDecisions() {
  const [result, setResult] = useState(null)
  const [demoLoading, setDemoLoading] = useState(null)
  const [demoError, setDemoError] = useState(null)

  const runDemo = async (key) => {
    setDemoLoading(key)
    setDemoError(null)
    setResult(null)
    try {
      const res = await api.runArgusDemo(key)
      setResult(res)
    } catch (e) {
      setDemoError(e.message)
    } finally {
      setDemoLoading(null)
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="PS15 — PromptGuard"
        title="ARGUS Decisions"
        subtitle="Every proposed critical action passes through PromptGuard detection, then deterministic policy, before the ARGUS Critical Decision Simulator may execute it."
      />

      {/* Demo buttons */}
      <div style={styles.scenariosGrid}>
        {SCENARIOS.map(s => (
          <button
            key={s.key}
            style={{ ...styles.scenarioBtn, borderColor: s.color }}
            onClick={() => runDemo(s.key)}
            disabled={demoLoading !== null}
          >
            <div style={{ ...styles.scenarioBadge, color: s.color }}>{s.label}</div>
            <div style={styles.scenarioDesc}>{s.desc}</div>
            {demoLoading === s.key && <div style={styles.spinner}>Running…</div>}
          </button>
        ))}
      </div>

      {demoError && <div style={styles.error}>{demoError}</div>}

      {/* Manual form + result side by side */}
      <div style={styles.twoCol}>
        <ManualForm onResult={r => { setResult(r); setDemoError(null) }} />
        {result && (
          <div style={styles.traceWrapper}>
            <div style={styles.traceWrapTitle}>Security Flow Trace</div>
            <FlowTrace result={result} />
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Styles (inline, matching existing page conventions)
// ---------------------------------------------------------------------------
const styles = {
  scenariosGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, 1fr)',
    gap: 12,
    marginBottom: 28,
  },
  scenarioBtn: {
    background: 'var(--surface-raised)',
    border: '1.5px solid',
    borderRadius: 'var(--radius-lg)',
    padding: '14px 16px',
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'opacity .15s',
  },
  scenarioBadge: {
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    fontWeight: 700,
    marginBottom: 6,
    letterSpacing: '0.04em',
  },
  scenarioDesc: { fontSize: 12.5, color: 'var(--text-muted)', lineHeight: 1.5 },
  spinner: { marginTop: 6, fontSize: 11.5, color: 'var(--signal)', fontFamily: 'var(--font-mono)' },
  twoCol: {
    display: 'grid',
    gridTemplateColumns: '360px 1fr',
    gap: 24,
    alignItems: 'start',
  },
  form: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 20,
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
  },
  formTitle: { fontWeight: 700, fontSize: 13.5, marginBottom: 4 },
  label: { fontSize: 12, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' },
  input: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    padding: '7px 10px',
    fontSize: 13,
    outline: 'none',
  },
  textarea: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    padding: '7px 10px',
    fontSize: 13,
    resize: 'vertical',
    fontFamily: 'inherit',
    outline: 'none',
  },
  select: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    padding: '7px 10px',
    fontSize: 13,
  },
  btn: {
    marginTop: 8,
    background: 'var(--signal-dim)',
    color: 'var(--signal)',
    border: '1px solid var(--signal)',
    borderRadius: 'var(--radius-sm)',
    padding: '9px 16px',
    fontSize: 13,
    fontWeight: 700,
    cursor: 'pointer',
  },
  error: {
    marginTop: 4,
    color: 'var(--tier-high)',
    background: 'var(--tier-high-bg)',
    padding: '8px 12px',
    borderRadius: 'var(--radius-sm)',
    fontSize: 12.5,
  },
  traceWrapper: {},
  traceWrapTitle: { fontWeight: 700, fontSize: 13.5, marginBottom: 10 },
  traceCard: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 20,
    display: 'flex',
    flexDirection: 'column',
    gap: 14,
  },
  traceHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  traceLabel: { fontWeight: 700, fontSize: 13 },
  traceId: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' },
  section: {},
  sectionLabel: { fontSize: 11.5, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginBottom: 4 },
  promptText: {
    fontSize: 13,
    color: 'var(--text-primary)',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '8px 10px',
    lineHeight: 1.5,
  },
  pre: {
    margin: 0,
    fontSize: 11.5,
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '8px 10px',
    overflowX: 'auto',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
  },
  gateRow: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: 6,
    flexWrap: 'wrap',
  },
  gateBox: {
    flex: '1 1 120px',
    minWidth: 100,
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '10px 12px',
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
  },
  gateTitle: { fontSize: 10.5, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', marginBottom: 2 },
  gateVerdict: { fontSize: 13.5, fontWeight: 800, letterSpacing: '0.04em' },
  gateDetail: { fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.4 },
  explanation: {
    marginTop: 6,
    fontSize: 11.5,
    color: 'var(--text-muted)',
    borderTop: '1px solid var(--border)',
    paddingTop: 6,
    lineHeight: 1.5,
  },
  expandBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--text-dim)',
    fontSize: 11,
    cursor: 'pointer',
    padding: 0,
    fontFamily: 'var(--font-mono)',
  },
  arrow: {
    fontSize: 18,
    color: 'var(--text-dim)',
    alignSelf: 'center',
    flexShrink: 0,
  },
  receipt: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    background: '#052e16',
    border: '1px solid #166534',
    borderRadius: 'var(--radius-sm)',
    padding: '8px 12px',
  },
  receiptLabel: { fontSize: 11, fontFamily: 'var(--font-mono)', color: '#4ade80' },
  receiptId: { fontSize: 12, fontFamily: 'var(--font-mono)', color: '#86efac', fontWeight: 700 },
}
