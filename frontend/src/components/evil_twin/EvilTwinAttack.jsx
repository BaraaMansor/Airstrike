import React, { useState, useEffect } from "react";

const API_BASE = "/api/evil-twin";

const EvilTwinAttack = () => {
  // Form state
  const [ssid, setSsid] = useState("");
  const [iface, setIface] = useState("");
  const [channel, setChannel] = useState("");
  // Status/logs
  const [status, setStatus] = useState(null);
  const [logs, setLogs] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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
    <div className="max-w-2xl mx-auto bg-white dark:bg-gray-900 rounded-lg shadow p-8 mt-8">
      <h2 className="text-2xl font-bold mb-6 text-gray-900 dark:text-white flex items-center">
        <span className="inline-block w-2 h-6 bg-red-500 rounded-full mr-3"></span>
        Evil Twin Attack
      </h2>
      <form
        onSubmit={e => {
          e.preventDefault();
          handleStart();
        }}
        className="space-y-4 mb-6"
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
          <label className="w-28 font-medium text-gray-700 dark:text-gray-200">SSID:</label>
          <input
            type="text"
            value={ssid}
            onChange={e => setSsid(e.target.value)}
            required
            className="flex-1 px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-400 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white"
            disabled={loading || (status && status.running)}
          />
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
          <label className="w-28 font-medium text-gray-700 dark:text-gray-200">Interface:</label>
          {interfaces.length > 0 ? (
            <select
              value={iface}
              onChange={e => setIface(e.target.value)}
              required
              className="flex-1 px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-400 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white"
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
              className="flex-1 px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-400 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white"
              disabled={loading || (status && status.running)}
            />
          )}
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
          <label className="w-28 font-medium text-gray-700 dark:text-gray-200">Channel:</label>
          <input
            type="text"
            value={channel}
            onChange={e => setChannel(e.target.value)}
            required
            className="flex-1 px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-red-400 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white"
            disabled={loading || (status && status.running)}
          />
        </div>
        <div className="flex gap-4 mt-4">
          <button
            type="submit"
            disabled={loading || (status && status.running)}
            className="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-6 rounded shadow transition disabled:opacity-60 disabled:cursor-not-allowed"
          >
            Start Attack
          </button>
          <button
            type="button"
            onClick={handleStop}
            disabled={loading || !(status && status.running)}
            className="bg-gray-700 hover:bg-gray-800 text-white font-bold py-2 px-6 rounded shadow transition disabled:opacity-60 disabled:cursor-not-allowed"
          >
            Stop Attack
          </button>
        </div>
      </form>

      {error && (
        <div className="text-red-600 font-medium mb-4">{error}</div>
      )}

      <div className="mb-4">
        <strong className="text-gray-800 dark:text-gray-100">Status:</strong>
        <pre className="bg-gray-100 dark:bg-gray-800 rounded p-3 mt-1 text-sm text-gray-900 dark:text-gray-100 overflow-x-auto">
          {status ? JSON.stringify(status, null, 2) : "No status yet."}
        </pre>
      </div>

      <div>
        <div className="flex items-center mb-2">
          <strong className="text-gray-800 dark:text-gray-100">Logs:</strong>
          <button
            onClick={handleRefreshLogs}
            className="ml-4 px-3 py-1 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-100 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition"
            type="button"
          >
            Refresh Logs
          </button>
        </div>
        <pre className="bg-gray-100 dark:bg-gray-800 rounded p-3 min-h-[100px] text-xs text-gray-900 dark:text-gray-100 overflow-y-auto max-h-64">
          {logs.length ? logs.join("\n") : "No logs yet."}
        </pre>
      </div>
    </div>
  );
};

export default EvilTwinAttack; 