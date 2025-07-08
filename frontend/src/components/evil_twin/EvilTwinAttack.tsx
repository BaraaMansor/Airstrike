import React, { useState, useEffect } from "react";

const API_BASE = "/api/evil-twin";

interface Status {
  running: boolean;
  pid?: number;
  error?: string;
}

const EvilTwinAttack: React.FC = () => {
  // Form state
  const [ssid, setSsid] = useState("");
  const [iface, setIface] = useState("");
  const [channel, setChannel] = useState("");
  // Status/logs
  const [status, setStatus] = useState<Status | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch available interfaces (optional, on mount)
  useEffect(() => {
    fetch(`${API_BASE}/interfaces`)
      .then(res => res.json())
      .then(data => setInterfaces(data))
      .catch(() => setInterfaces([]));
  }, []);

  // Fetch status (on mount and after actions)
  const fetchStatus = () => {
    fetch(`${API_BASE}/status`)
      .then(res => res.json())
      .then(data => setStatus(data))
      .catch(() => setStatus(null));
  };

  // Fetch logs
  const fetchLogs = () => {
    fetch(`${API_BASE}/logs?lines=50`)
      .then(res => res.json())
      .then(data => setLogs(data.logs || []))
      .catch(() => setLogs([]));
  };

  // Initial fetch
  useEffect(() => {
    fetchStatus();
    fetchLogs();
  }, []);

  // Handlers
  const handleStart = () => {
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid, interface: iface, channel })
    })
      .then(res => res.json())
      .then(data => {
        setStatus(data);
        if (data.error) setError(data.error);
        fetchLogs();
      })
      .catch(() => setError("Failed to start attack."))
      .finally(() => setLoading(false));
  };

  const handleStop = () => {
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/stop`, { method: "POST" })
      .then(res => res.json())
      .then(data => {
        setStatus(data);
        if (data.error) setError(data.error);
        fetchLogs();
      })
      .catch(() => setError("Failed to stop attack."))
      .finally(() => setLoading(false));
  };

  const handleRefreshLogs = () => {
    fetchLogs();
  };

  return (
    <div style={{ maxWidth: 600, margin: "0 auto", padding: 24 }}>
      <h2>Evil Twin Attack</h2>
      <form
        onSubmit={e => {
          e.preventDefault();
          handleStart();
        }}
        style={{ marginBottom: 24 }}
      >
        <div>
          <label>SSID:</label>
          <input
            type="text"
            value={ssid}
            onChange={e => setSsid(e.target.value)}
            required
            style={{ marginLeft: 8 }}
            disabled={loading || (status && status.running)}
          />
        </div>
        <div>
          <label>Interface:</label>
          {interfaces.length > 0 ? (
            <select
              value={iface}
              onChange={e => setIface(e.target.value)}
              required
              style={{ marginLeft: 8 }}
              disabled={loading || (status && status.running)}
            >
              <option value="">Select interface</option>
              {interfaces.map(i => (
                <option key={i} value={i}>{i}</option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              value={iface}
              onChange={e => setIface(e.target.value)}
              required
              style={{ marginLeft: 8 }}
              disabled={loading || (status && status.running)}
            />
          )}
        </div>
        <div>
          <label>Channel:</label>
          <input
            type="text"
            value={channel}
            onChange={e => setChannel(e.target.value)}
            required
            style={{ marginLeft: 8 }}
            disabled={loading || (status && status.running)}
          />
        </div>
        <button type="submit" disabled={loading || (status && status.running)} style={{ marginTop: 12 }}>
          Start Attack
        </button>
        <button type="button" onClick={handleStop} disabled={loading || !(status && status.running)} style={{ marginLeft: 8 }}>
          Stop Attack
        </button>
      </form>

      {error && (
        <div style={{ color: "red", marginBottom: 12 }}>{error}</div>
      )}

      <div>
        <strong>Status:</strong>
        <pre>{status ? JSON.stringify(status, null, 2) : "No status yet."}</pre>
      </div>

      <div>
        <strong>Logs:</strong>
        <button onClick={handleRefreshLogs} style={{ marginLeft: 8 }}>
          Refresh Logs
        </button>
        <pre style={{ background: "#f5f5f5", padding: 12, minHeight: 100 }}>
          {logs.length ? logs.join("\n") : "No logs yet."}
        </pre>
      </div>
    </div>
  );
};

export default EvilTwinAttack; 