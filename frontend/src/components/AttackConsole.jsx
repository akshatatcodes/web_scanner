import { useEffect, useRef, useState } from 'react';

const TYPE_CONFIG = {
  SEND:  { icon: '→', color: '#60a5fa', label: 'SEND' },
  RECV:  { icon: '←', color: '#a78bfa', label: 'RECV' },
  FOUND: { icon: '⚠', color: '#f87171', label: 'FOUND' },
  INFO:  { icon: '·', color: '#9ca3af', label: 'INFO' },
  ERROR: { icon: '✕', color: '#ef4444', label: 'ERR' },
};

const SEV_COLOR = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#f59e0b',
  LOW:      '#22d3ee',
};

const MAX_LINES = 200;

const AttackConsole = ({ isActive, onNewFinding }) => {
  const [logs, setLogs] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const [filter, setFilter] = useState('ALL');
  const bottomRef = useRef(null);
  const esRef = useRef(null);

  useEffect(() => {
    if (!isActive) return;

    // Connect SSE dynamically
    const API_BASE = import.meta.env.VITE_API_BASE || `http://${window.location.hostname}:5000/api`;
    const es = new EventSource(`${API_BASE}/attack-stream`);
    esRef.current = es;

    es.onopen = () => {
      setLogs([{
        ts: Date.now(),
        type: 'INFO',
        scanner: 'System',
        result: 'Connected to attack stream. Waiting for payloads...'
      }]);
    };

    es.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data);
        setLogs(prev => {
          const next = [...prev, entry];
          return next.length > MAX_LINES ? next.slice(-MAX_LINES) : next;
        });
        if (entry.type === 'FOUND' && onNewFinding) onNewFinding(entry);
      } catch {}
    };

    es.onerror = () => {
      // silently handle disconnect
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [isActive]);

  // Auto-scroll to bottom unless paused
  useEffect(() => {
    if (!isPaused && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, isPaused]);

  const filtered = filter === 'ALL' ? logs : logs.filter(l => l.type === filter);

  if (!isActive && logs.length === 0) return null;

  return (
    <div style={{
      background: '#0a0a0f',
      border: '1px solid rgba(139,92,246,0.25)',
      borderRadius: '14px',
      overflow: 'hidden',
      marginTop: '1.5rem',
      boxShadow: '0 0 40px rgba(139,92,246,0.08)',
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
    }}>
      {/* Terminal Header */}
      <div style={{
        background: 'rgba(139,92,246,0.08)',
        borderBottom: '1px solid rgba(139,92,246,0.2)',
        padding: '0.7rem 1.2rem',
        display: 'flex',
        alignItems: 'center',
        gap: '1rem',
        flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#ef4444', display: 'inline-block' }} />
          <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#f59e0b', display: 'inline-block' }} />
          <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
        </div>
        <span style={{ color: '#a78bfa', fontSize: '0.8rem', fontWeight: 700, letterSpacing: '0.08em' }}>
          LIVE ATTACK CONSOLE {isActive && <span style={{ color: '#10b981', animation: 'pulse 1s infinite' }}>● LIVE</span>}
        </span>
        <span style={{ color: '#4b5563', fontSize: '0.72rem', marginLeft: 'auto' }}>
          {logs.length} events
        </span>

        {/* Filter tabs */}
        <div style={{ display: 'flex', gap: '0.3rem' }}>
          {['ALL', 'SEND', 'RECV', 'FOUND'].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              background: filter === f ? 'rgba(139,92,246,0.2)' : 'transparent',
              color: filter === f ? '#a78bfa' : '#4b5563',
              border: `1px solid ${filter === f ? 'rgba(139,92,246,0.4)' : 'rgba(255,255,255,0.05)'}`,
              borderRadius: '5px',
              padding: '0.15rem 0.55rem',
              fontSize: '0.68rem',
              fontWeight: 700,
              cursor: 'pointer',
              fontFamily: 'inherit',
            }}>{f}</button>
          ))}
          <button onClick={() => setIsPaused(p => !p)} style={{
            background: isPaused ? 'rgba(245,158,11,0.2)' : 'transparent',
            color: isPaused ? '#f59e0b' : '#4b5563',
            border: '1px solid rgba(255,255,255,0.05)',
            borderRadius: '5px',
            padding: '0.15rem 0.55rem',
            fontSize: '0.68rem',
            cursor: 'pointer',
            fontFamily: 'inherit',
          }}>{isPaused ? '▶ RESUME' : '⏸ PAUSE'}</button>
          <button onClick={() => setLogs([])} style={{
            background: 'transparent',
            color: '#4b5563',
            border: '1px solid rgba(255,255,255,0.05)',
            borderRadius: '5px',
            padding: '0.15rem 0.55rem',
            fontSize: '0.68rem',
            cursor: 'pointer',
            fontFamily: 'inherit',
          }}>CLEAR</button>
        </div>
      </div>

      {/* Terminal Body */}
      <div style={{
        height: '280px',
        overflowY: 'auto',
        padding: '0.8rem 1.2rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1px',
      }}>
        {filtered.length === 0 ? (
          <div style={{ color: '#374151', fontSize: '0.78rem', marginTop: '2rem', textAlign: 'center' }}>
            {isActive ? '⌛ Waiting for attack events...' : 'No events recorded yet.'}
          </div>
        ) : (
          filtered.map((log, i) => <LogLine key={i} log={log} />)
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};

const LogLine = ({ log }) => {
  const cfg = TYPE_CONFIG[log.type] || TYPE_CONFIG.INFO;
  const sevColor = log.severity ? SEV_COLOR[log.severity] || '#9ca3af' : null;
  const time = new Date(log.ts).toLocaleTimeString('en-GB', { hour12: false });

  return (
    <div style={{
      display: 'flex',
      alignItems: 'baseline',
      gap: '0.6rem',
      fontSize: '0.73rem',
      lineHeight: 1.7,
      borderLeft: log.type === 'FOUND' ? `2px solid ${sevColor || cfg.color}` : '2px solid transparent',
      paddingLeft: '0.4rem',
      background: log.type === 'FOUND' ? `${sevColor}0a` : 'transparent',
      borderRadius: '2px',
    }}>
      {/* Timestamp */}
      <span style={{ color: '#374151', minWidth: '62px', flexShrink: 0 }}>{time}</span>

      {/* Scanner badge */}
      <span style={{
        color: '#6b7280',
        background: 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '3px',
        padding: '0 4px',
        fontSize: '0.64rem',
        minWidth: '60px',
        textAlign: 'center',
        flexShrink: 0,
      }}>{log.scanner || '—'}</span>

      {/* Type badge */}
      <span style={{ color: cfg.color, fontWeight: 700, minWidth: '40px', flexShrink: 0 }}>
        {cfg.icon} {cfg.label}
      </span>

      {/* URL (truncated) */}
      {log.url && (
        <span style={{ color: '#6b7280', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '240px', flexShrink: 1 }}>
          {log.url.replace(/^https?:\/\/[^/]+/, '')}
        </span>
      )}

      {/* Payload */}
      {log.payload && log.type === 'SEND' && (
        <span style={{ color: '#f59e0b', background: 'rgba(245,158,11,0.08)', borderRadius: '3px', padding: '0 4px', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 1 }}>
          {log.payload.length > 40 ? log.payload.slice(0, 40) + '…' : log.payload}
        </span>
      )}

      {/* Status code */}
      {log.status !== undefined && log.type === 'RECV' && (
        <span style={{ color: log.status < 400 ? '#10b981' : '#ef4444', flexShrink: 0 }}>
          {log.status}
        </span>
      )}

      {/* Result / finding */}
      {log.result && (
        <span style={{ color: log.type === 'FOUND' ? (sevColor || cfg.color) : '#9ca3af', fontWeight: log.type === 'FOUND' ? 700 : 400, flexShrink: 1 }}>
          {log.result}
        </span>
      )}

      {/* Severity pill */}
      {log.severity && (
        <span style={{
          color: sevColor,
          background: `${sevColor}18`,
          border: `1px solid ${sevColor}44`,
          borderRadius: '4px',
          padding: '0 5px',
          fontSize: '0.63rem',
          fontWeight: 800,
          letterSpacing: '0.05em',
          flexShrink: 0,
        }}>{log.severity}</span>
      )}
    </div>
  );
};

export default AttackConsole;
