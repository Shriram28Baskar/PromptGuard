import { Routes, Route, NavLink } from 'react-router-dom'
import AegisChat from './pages/AegisChat'
import Playground from './pages/Playground'
import Dashboard from './pages/Dashboard'
import Logs from './pages/Logs'
import ArgusDecisions from './pages/ArgusDecisions'
import IndirectInjectionDemo from './pages/IndirectInjectionDemo'

const NAV_ITEMS = [
  { to: '/', label: 'Aegis Chat', icon: 'A' },
  { to: '/playground', label: 'Gateway Lab', icon: '>' },
  { to: '/dashboard', label: 'Evaluation', icon: '#' },
  { to: '/logs', label: 'Audit Logs', icon: '=' },
  { to: '/argus', label: 'ARGUS Decisions', icon: '⚡' },
  { to: '/indirect-demo', label: 'Indirect Injection', icon: '🛡️' },
]

export default function App() {
  return (
    <div style={styles.shell}>
      <aside style={styles.sidebar}>
        <div style={styles.brand}>
          <div style={styles.brandMark}>A</div>
          <div>
            <div style={styles.brandName}>Aegis</div>
            <div style={styles.brandSub}>Injection Gateway</div>
          </div>
        </div>

        <nav style={styles.nav}>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              style={({ isActive }) => ({
                ...styles.navLink,
                ...(isActive ? styles.navLinkActive : {}),
              })}
            >
              <span style={styles.navIcon}>{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div style={styles.footer}>
          <div style={styles.footerLine}>OWASP LLM Top 10 - #1</div>
          <div style={styles.footerLine}>Prompt Injection</div>
        </div>
      </aside>

      <main style={styles.main}>
        <Routes>
          <Route path="/" element={<AegisChat />} />
          <Route path="/playground" element={<Playground />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/argus" element={<ArgusDecisions />} />
          <Route path="/indirect-demo" element={<IndirectInjectionDemo />} />
        </Routes>
      </main>
    </div>
  )
}

const styles = {
  shell: { display: 'flex', minHeight: '100vh' },
  sidebar: {
    width: 220,
    flexShrink: 0,
    borderRight: '1px solid var(--border)',
    padding: '24px 16px',
    display: 'flex',
    flexDirection: 'column',
    position: 'sticky',
    top: 0,
    height: '100vh',
  },
  brand: { display: 'flex', alignItems: 'center', gap: 10, padding: '0 8px', marginBottom: 32 },
  brandMark: {
    width: 34,
    height: 34,
    borderRadius: 10,
    background: 'var(--signal-dim)',
    color: 'var(--signal)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: 16,
    fontWeight: 900,
  },
  brandName: { fontWeight: 800, fontSize: 15, letterSpacing: 0 },
  brandSub: { fontSize: 10.5, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' },
  nav: { display: 'flex', flexDirection: 'column', gap: 2 },
  navLink: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '10px 12px',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-muted)',
    fontSize: 13.5,
    fontWeight: 500,
  },
  navLinkActive: { background: 'var(--surface-raised)', color: 'var(--text-primary)' },
  navIcon: {
    color: 'var(--signal)',
    fontSize: 12,
    width: 14,
    textAlign: 'center',
    fontFamily: 'var(--font-mono)',
    fontWeight: 700,
  },
  footer: { marginTop: 'auto', padding: '0 8px' },
  footerLine: { fontSize: 10.5, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', lineHeight: 1.6 },
  main: { flex: 1, padding: '32px 40px', maxWidth: 1440, width: '100%' },
}
