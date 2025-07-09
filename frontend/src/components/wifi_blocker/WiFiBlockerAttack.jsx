import React, { useState, useEffect } from "react";

const API_BASE = "/api/wifi-blocker";

const WiFiBlockerAttack = () => {
  // Form state
  const [iface, setIface] = useState("");
  // Status/logs
  const [status, setStatus] = useState(null);
  const [logs, setLogs] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  // Client scanning and selection
  const [clients, setClients] = useState([]);
  const [selectedClients, setSelectedClients] = useState([]);
  const [scanning, setScanning] = useState(false);
  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  // Auto-refresh logs during attack
  const [logRefreshInterval, setLogRefreshInterval] = useState(null);

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

  // Auto-refresh logs when attack is running
  useEffect(() => {
    if (status && status.running) {
      // Start auto-refresh
      const interval = setInterval(fetchLogs, 2000); // Refresh every 2 seconds
      setLogRefreshInterval(interval);
      
      return () => {
        if (interval) {
          clearInterval(interval);
          setLogRefreshInterval(null);
        }
      };
    } else {
      // Stop auto-refresh
      if (logRefreshInterval) {
        clearInterval(logRefreshInterval);
        setLogRefreshInterval(null);
      }
    }
  }, [status?.running]);

  // Scan for clients
  const handleScan = () => {
    if (!iface) {
      setError("Please select an interface first.");
      return;
    }
    
    setScanning(true);
    setError(null);
    fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface })
    })
      .then(res => res.json())
      .then(data => {
        setClients(data.clients || []);
        setSelectedClients([]);
        if (data.clients && data.clients.length === 0) {
          setError("No clients found on the network.");
        }
      })
      .catch(() => setError("Failed to scan for clients."))
      .finally(() => setScanning(false));
  };

  // Handle client selection
  const handleClientToggle = (clientIp) => {
    setSelectedClients(prev => 
      prev.includes(clientIp) 
        ? prev.filter(ip => ip !== clientIp)
        : [...prev, clientIp]
    );
  };

  // Handle select all
  const handleSelectAll = () => {
    setSelectedClients(clients.map(client => client.ip));
  };

  // Handle deselect all
  const handleDeselectAll = () => {
    setSelectedClients([]);
  };

  // Handlers
  const handleStart = () => {
    if (!iface) {
      setError("Please select an interface first.");
      return;
    }
    
    if (selectedClients.length === 0) {
      setError("Please select at least one client to block.");
      return;
    }

    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        interface: iface, 
        target_ips: selectedClients 
      })
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

  // Format log entries for better display
  const formatLogEntry = (log) => {
    if (log.includes("🟢 ONLINE")) {
      return <span className="text-green-600 font-medium">{log}</span>;
    } else if (log.includes("🔴 BLOCKED")) {
      return <span className="text-red-600 font-medium">{log}</span>;
    } else if (log.includes("Error:")) {
      return <span className="text-red-500">{log}</span>;
    } else if (log.includes("🔥 Attack started")) {
      return <span className="text-blue-600 font-bold">{log}</span>;
    } else if (log.includes("🔒 Blocked:")) {
      return <span className="text-orange-600 font-medium">{log}</span>;
    }
    return log;
  };

  return (
    <div className="max-w-2xl mx-auto bg-white dark:bg-gray-900 rounded-lg shadow p-8 mt-8">
      <h2 className="text-2xl font-bold mb-6 text-gray-900 dark:text-white flex items-center">
        <span className="inline-block w-2 h-6 bg-blue-500 rounded-full mr-3"></span>
        Wi-Fi Blocker Attack
      </h2>
      
      {/* Interface Selection */}
      <div className="space-y-4 mb-6">
        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
          <label className="w-28 font-medium text-gray-700 dark:text-gray-200">Interface:</label>
          {interfaces.length > 0 ? (
            <select
              value={iface}
              onChange={e => setIface(e.target.value)}
              required
              className="flex-1 px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white"
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
              className="flex-1 px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-400 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white"
              disabled={loading || (status && status.running)}
              placeholder="e.g., wlan0"
            />
          )}
        </div>
        
        {/* Scan Button */}
        <div className="flex gap-4">
          <button
            type="button"
            onClick={handleScan}
            disabled={scanning || loading || (status && status.running)}
            className="bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-6 rounded shadow transition disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {scanning ? "Scanning..." : "Scan for Clients"}
          </button>
        </div>
      </div>

      {/* Client Selection */}
      {clients.length > 0 && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Discovered Clients ({clients.length})
            </h3>
            <div className="flex gap-2">
              <button
                onClick={handleSelectAll}
                className="px-3 py-1 bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded hover:bg-blue-200 dark:hover:bg-blue-800 transition text-sm"
              >
                Select All
              </button>
              <button
                onClick={handleDeselectAll}
                className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-600 transition text-sm"
              >
                Deselect All
              </button>
            </div>
          </div>
          
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {clients.map((client, index) => (
              <div
                key={client.ip}
                className={`p-3 border rounded-lg cursor-pointer transition ${
                  selectedClients.includes(client.ip)
                    ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                    : 'border-gray-200 dark:border-gray-700 hover:border-blue-300'
                }`}
                onClick={() => handleClientToggle(client.ip)}
              >
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    checked={selectedClients.includes(client.ip)}
                    onChange={() => handleClientToggle(client.ip)}
                    className="mr-3 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <div>
                    <div className="font-medium text-gray-900 dark:text-white">
                      {client.ip}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      MAC: {client.mac}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
          
          {selectedClients.length > 0 && (
            <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div className="text-sm font-medium text-blue-800 dark:text-blue-200">
                Selected: {selectedClients.length} client{selectedClients.length !== 1 ? 's' : ''}
              </div>
              <div className="text-xs text-blue-600 dark:text-blue-300 mt-1">
                {selectedClients.join(', ')}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Attack Controls */}
      <div className="flex gap-4 mt-6">
        <button
          type="button"
          onClick={handleStart}
          disabled={loading || (status && status.running) || selectedClients.length === 0}
          className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-6 rounded shadow transition disabled:opacity-60 disabled:cursor-not-allowed"
        >
          Start Blocking
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

      {error && (
        <div className="text-red-600 font-medium mb-4 mt-4">{error}</div>
      )}

      <div className="mb-4 mt-6">
        <strong className="text-gray-800 dark:text-gray-100">Status:</strong>
        <pre className="bg-gray-100 dark:bg-gray-800 rounded p-3 mt-1 text-sm text-gray-900 dark:text-gray-100 overflow-x-auto">
          {status ? (
            <div>
              <div><strong>Running:</strong> {status.running ? 'Yes' : 'No'}</div>
              {status.pid && <div><strong>PID:</strong> {status.pid}</div>}
              {status.targets && (
                <div>
                  <strong>Targets:</strong> {status.targets.join(', ')}
                </div>
              )}
              {status.message && (
                <div>
                  <strong>Message:</strong> {status.message}
                </div>
              )}
              {status.error && (
                <div className="text-red-600">
                  <strong>Error:</strong> {status.error}
                </div>
              )}
            </div>
          ) : "No status yet."}
        </pre>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <strong className="text-gray-800 dark:text-gray-100">
            Live Logs {status && status.running && <span className="text-green-500">●</span>}
          </strong>
          <button
            onClick={handleRefreshLogs}
            className="px-3 py-1 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-100 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition"
            type="button"
          >
            Refresh Logs
          </button>
        </div>
        <pre className="bg-gray-100 dark:bg-gray-800 rounded p-3 min-h-[200px] text-xs text-gray-900 dark:text-gray-100 overflow-y-auto max-h-64">
          {logs.length > 0 ? (
            <div className="space-y-1">
              {logs.map((log, index) => (
                <div key={index} className="font-mono">
                  {formatLogEntry(log)}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-gray-500 italic">No logs yet. Start an attack to see live status updates.</div>
          )}
        </pre>
      </div>
    </div>
  );
};

export default WiFiBlockerAttack; 