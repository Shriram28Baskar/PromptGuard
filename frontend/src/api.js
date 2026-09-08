const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`${res.status} ${res.statusText}: ${text}`)
  }
  return res.json()
}

export const api = {
  chat: (prompt, sessionId, history = []) =>
    request('/chat', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId, history }),
    }),

  directChat: (prompt, sessionId, history = []) =>
    request('/chat/direct', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId, history }),
    }),

  detect: (prompt, sessionId = null, source = 'user_message') =>
    request('/detect', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId, source }),
    }),

  simulate: (sessionId, turns) =>
    request('/simulate', {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId, turns }),
    }),

  getLogs: (tier = null, limit = 200) => {
    const params = new URLSearchParams({ limit })
    if (tier) params.set('tier', tier)
    return request(`/logs?${params.toString()}`)
  },

  clearLogs: () => request('/logs', { method: 'DELETE' }),

  getStatistics: () => request('/statistics'),

  runStressTest: () => request('/stress-test'),

  // PS15 — ARGUS Critical Decision Simulator
  proposeAction: (prompt, sessionId, proposedAction) =>
    request('/argus/propose', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId, proposed_action: proposedAction }),
    }),

  runArgusDemo: (scenario) => request(`/argus/demo/${scenario}`),

  // Indirect Injection Demo (/agent-demo)
  agentDemo: (scenario, customDocument = null) =>
    request('/agent-demo', {
      method: 'POST',
      body: JSON.stringify({ scenario, custom_document: customDocument }),
    }),

  getAgentDemoScenarios: () => request('/agent-demo/scenarios'),
}

