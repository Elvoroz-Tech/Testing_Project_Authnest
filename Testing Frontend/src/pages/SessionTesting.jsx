import { useCallback, useEffect, useState } from 'react';
import { useAuthNest } from '@elvoroz/authnest-react';
import { getLocalSession, renewSession, fetchServerSession, simulateAccessTokenExpiry, onSessionEvent } from '../utils/sessionRenewal';

// A page for testing the session behaviour of the newer AuthNest:
//   1-hour access token · rotating 30-day refresh token · silent renewal · real logout.
// Sign in first (Login button in the navbar), then try the buttons.

const fmt = (ms) => {
  if (ms === null || ms === undefined) return '—';
  if (ms <= 0) return 'expired';
  const s = Math.round(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`;
};

const SessionTesting = () => {
  const { authStatus } = useAuthNest();
  const [local, setLocal] = useState(getLocalSession());
  const [server, setServer] = useState(null);
  const [events, setEvents] = useState([]);
  const [output, setOutput] = useState(null);
  const [busy, setBusy] = useState(false);

  const refreshServerView = useCallback(async () => setServer(await fetchServerSession()), []);

  useEffect(() => {
    const tick = setInterval(() => setLocal(getLocalSession()), 1000);
    const off = onSessionEvent((e) => setEvents((prev) => [{ ...e, id: `${e.at.getTime()}-${prev.length}` }, ...prev].slice(0, 12)));
    refreshServerView();
    return () => { clearInterval(tick); off(); };
  }, [refreshServerView]);

  const run = async (label, fn) => {
    setBusy(true);
    try { setOutput({ label, ...(await fn()) }); } catch (e) { setOutput({ label, error: e.message }); }
    setBusy(false);
    setLocal(getLocalSession());
    refreshServerView();
  };

  const callGetUserData = () => run('GET /api/authnest/getUserData', async () => {
    const res = await fetch('/api/authnest/getUserData', { credentials: 'include' });
    const body = await res.json().catch(() => ({}));
    return { status: res.status, body: res.ok ? { success: body.success, name: body.data?.name, email: body.data?.email } : body };
  });

  const card = { background: '#fff', borderRadius: 12, padding: '1rem 1.25rem', boxShadow: '0 4px 16px rgba(0,0,0,.08)', marginBottom: '1rem' };
  const btn = { padding: '.55rem .9rem', marginRight: '.5rem', marginBottom: '.5rem', borderRadius: 8, border: '1px solid #667eea', background: '#fff', cursor: 'pointer' };
  const row = { display: 'flex', justifyContent: 'space-between', padding: '.25rem 0', borderBottom: '1px solid #eee' };

  return (
    <div style={{ maxWidth: 820, margin: '1.5rem auto', padding: '0 1rem', textAlign: 'left' }}>
      <h1>Session testing</h1>
      <p>Sign-in status in the SDK: <strong>{authStatus.isLoading ? 'checking…' : authStatus.isAuthenticated ? 'signed in' : 'signed out'}</strong></p>

      <div style={card}>
        <h3 style={{ marginTop: 0 }}>What this browser holds</h3>
        <div style={row}><span>Access token cookie (1 hour)</span><strong>{local.hasAccess ? `present · expires in ${fmt(local.accessExpiresInMs)}` : 'not present'}</strong></div>
        <div style={row}><span>Refresh token cookie (30 days, rotates)</span><strong>{local.hasRefresh ? 'present' : 'not present'}</strong></div>
        <div style={row}><span>Backend's view (also sees httpOnly cookies)</span><strong>{server ? `${server.authenticated ? 'signed in' : 'signed out'}${server.renewable ? ' · renewable' : ''}${server.accessExpiresInSeconds != null ? ` · ${fmt(server.accessExpiresInSeconds * 1000)} left` : ''}` : '—'}</strong></div>
      </div>

      <div style={card}>
        <h3 style={{ marginTop: 0 }}>Try it</h3>
        <button style={btn} disabled={busy} onClick={() => run('Renew now', () => renewSession({ force: true }))}>Renew now</button>
        <button style={btn} disabled={busy} onClick={() => { simulateAccessTokenExpiry(); setLocal(getLocalSession()); window.dispatchEvent(new Event('authnest-testing:check-session')); }}>Simulate “an hour later”</button>
        <button style={btn} disabled={busy} onClick={callGetUserData}>Call getUserData</button>
        <button style={btn} disabled={busy} onClick={() => run('GET /api/authnest/session', async () => ({ body: await fetchServerSession() }))}>Ask the backend for status</button>
        <p style={{ fontSize: '.85rem', opacity: .75 }}>
          “Simulate an hour later” deletes the access-token cookie, exactly as the browser does when it expires. Within a moment the
          keeper renews it silently and you stay signed in — watch the events below. Use the navbar’s Log out to test that logging out
          really ends the session (a refresh afterwards must fail).
        </p>
        {output && <pre style={{ background: '#f6f6fb', padding: '.75rem', borderRadius: 8, overflow: 'auto' }}>{JSON.stringify(output, null, 2)}</pre>}
      </div>

      <div style={card}>
        <h3 style={{ marginTop: 0 }}>Session events</h3>
        {events.length === 0 && <p style={{ opacity: .7 }}>Nothing yet. Renewals appear here.</p>}
        <ul style={{ paddingLeft: '1.1rem', margin: 0 }}>
          {events.map((e) => (
            <li key={e.id}>{e.at.toLocaleTimeString()} — <strong>{e.type}</strong>{e.accessExpiresInSeconds ? ` (new token valid ${fmt(e.accessExpiresInSeconds * 1000)})` : ''}{e.message ? ` — ${e.message}` : ''}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default SessionTesting;
