"use client"

import { useState, useEffect, useRef } from "react"
import {
  Wifi,
  Shield,
  Zap,
  Users,
  Activity,
  AlertTriangle,
  Play,
  Square,
  RefreshCw,
  Search,
  Waves,
  Eye,
  Globe,
} from "lucide-react"
import AirstrikeAPI from "./services/api"
import "./App.css"
import EvilTwinAttack from "./components/evil_twin/EvilTwinAttack.jsx"
import WiFiBlockerAttack from "./components/wifi_blocker/WiFiBlockerAttack.jsx"

const App = () => {
  // API client
  const api = useRef(new AirstrikeAPI())

  // State management
  const [apiStatus, setApiStatus] = useState({ status: "unknown", attacks: 0 })
  const [accessPoints, setAccessPoints] = useState([])
  const [networkClients, setNetworkClients] = useState([])
  const [mitmClients, setMitmClients] = useState([])
  const [mitmTraffic, setMitmTraffic] = useState([])
  const [logs, setLogs] = useState({ deauth: [], icmp: [], mitm: [], handshake: [] })
  const [loading, setLoading] = useState({ scan: false, discover: false, mitmDiscover: false })
  const [errors, setErrors] = useState({})
  const [showEvilTwin, setShowEvilTwin] = useState(false)
  const [showWiFiBlocker, setShowWiFiBlocker] = useState(false)

  // Form states
  const [scanConfig, setScanConfig] = useState({
    interface: "wlan0",
    duration: 15,
    advanced: true,
  })

  const [deauthConfig, setDeauthConfig] = useState({
    interface: "wlan0",
    ssid: "",
    bssid: "",
    channel: 6,
  })

  const [icmpConfig, setIcmpConfig] = useState({
    interface: "wlan0",
    targetIP: "",
    packetSize: 64,
    delay: 0.001,
  })

  const [mitmConfig, setMitmConfig] = useState({
    interface: "wlan0",
    selectedTargets: [],
  })

  const [handshakeConfig, setHandshakeConfig] = useState({
    interface: "wlan0",
    ssid: "",
    bssid: "",
    channel: 6,
    wordlist: "/usr/share/wordlists/rockyou.txt",
    timeout: 60,
    deauthCount: 5,
    deauthInterval: 2.0,
  })

  // Attack states
  const [attackStates, setAttackStates] = useState({
    deauth: { running: false, id: null },
    icmp: { running: false, id: null },
    mitm: { running: false, id: null },
    handshake: { running: false, id: null },
    probeSniffer: { running: false, id: null },
  })

  // Polling intervals
  const pollingIntervals = useRef({})

  // Network Manager Button State
  const [networkActionResult, setNetworkActionResult] = useState(null);
  const [networkActionLoading, setNetworkActionLoading] = useState(false);

  // Wireless Interface Reset State
  const [wirelessResetResult, setWirelessResetResult] = useState(null);
  const [wirelessResetLoading, setWirelessResetLoading] = useState(false);

  // Probe Sniffer state
  const [probeSnifferConfig, setProbeSnifferConfig] = useState({
    interface: scanConfig.interface,
  });
  const [probeSnifferLoading, setProbeSnifferLoading] = useState(false);
  const [probeSnifferResult, setProbeSnifferResult] = useState(null);
  const [probeSnifferLogs, setProbeSnifferLogs] = useState([]);

  // Probe Sniffer summary for top bar
  const [probeSnifferSummary, setProbeSnifferSummary] = useState("");

  // Add a local state to track if the Probe Sniffer section is visible
  const [probeSnifferSectionActive, setProbeSnifferSectionActive] = useState(false);

  // Add function to fetch probe sniffer stats
  const fetchProbeSnifferStats = async () => {
    try {
      const res = await fetch('/api/probe-sniffer/status');
      const data = await res.json();
      if (data && data.running && data.stats) {
        setProbeSnifferSummary(
          `• ${data.stats.unique_clients || 0} clients, ${data.stats.unique_ssids || 0} SSIDs, ${data.stats.wildcard_probe_count || 0} wildcards`
        );
      } else {
        setProbeSnifferSummary("");
      }
    } catch {
      setProbeSnifferSummary("");
    }
  };

  // Add effect to fetch status when section becomes active
  useEffect(() => {
    if (probeSnifferSectionActive) {
      fetchProbeSnifferStats();
    }
  }, [probeSnifferSectionActive]);

  const handleNetworkAction = () => {
    setNetworkActionLoading(true);
    setNetworkActionResult(null);
    fetch(`/api/evil-twin/kill-adapter-and-restart-network`, {
      method: "POST"
    })
      .then(res => res.json())
      .then(data => setNetworkActionResult(data))
      .catch(() => setNetworkActionResult({ actions: [], errors: ["Request failed"] }))
      .finally(() => setNetworkActionLoading(false));
  };

  const handleWirelessReset = () => {
    setWirelessResetLoading(true);
    setWirelessResetResult(null);
    fetch(`/api/evil-twin/reset-wireless-interface`, {
      method: "POST"
    })
      .then(res => res.json())
      .then(data => setWirelessResetResult(data))
      .catch(() => setWirelessResetResult({ actions: [], errors: ["Request failed"] }))
      .finally(() => setWirelessResetLoading(false));
  };

  // WiFi Blocker state
  const [wifiBlockerConfig, setWiFiBlockerConfig] = useState({
    interface: scanConfig.interface,
    targets: "",
  });
  const [wifiBlockerLoading, setWiFiBlockerLoading] = useState(false);
  const [wifiBlockerResult, setWiFiBlockerResult] = useState(null);
  const [wifiBlockerScanLoading, setWiFiBlockerScanLoading] = useState(false);
  const [wifiBlockerScanResults, setWiFiBlockerScanResults] = useState([]);
  const handleWiFiBlockerScan = async () => {
    setWiFiBlockerScanLoading(true);
    setWiFiBlockerScanResults([]);
    setErrors((prev) => { const newErrors = { ...prev }; delete newErrors.wifiBlockerScan; return newErrors; });
    const result = await api.current.discoverClients(wifiBlockerConfig.interface);
    setWiFiBlockerScanLoading(false);
    if (result.success) {
      setWiFiBlockerScanResults(result.data.clients || []);
    } else {
      setError("wifiBlockerScan", result.error || "Scan failed");
    }
  };
  const handleWiFiBlockerSubmit = async (e) => {
    e.preventDefault();
    setWiFiBlockerLoading(true);
    setWiFiBlockerResult(null);
    setErrors((prev) => { const newErrors = { ...prev }; delete newErrors.wifiBlocker; return newErrors; });
    const targets = wifiBlockerConfig.targets.split(",").map(ip => ip.trim()).filter(ip => ip);
    if (!wifiBlockerConfig.interface || targets.length === 0) {
      setError("wifiBlocker", "Please provide interface and at least one target IP.");
      setWiFiBlockerLoading(false);
      return;
    }
    const result = await api.current.startWiFiBlocker(wifiBlockerConfig.interface, targets);
    setWiFiBlockerLoading(false);
    setWiFiBlockerResult(result.data);
  };

  // Probe Sniffer handlers
  const startProbeSniffer = async () => {
    setProbeSnifferLoading(true);
    setProbeSnifferResult(null);
    setErrors((prev) => { const newErrors = { ...prev }; delete newErrors.probeSniffer; return newErrors; });
    
    try {
      const response = await fetch('/api/probe-sniffer/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: probeSnifferConfig.interface })
      });
      
      const result = await response.json();
      setProbeSnifferLoading(false);
      
      if (result.running) {
        setAttackStates(prev => ({ ...prev, probeSniffer: { running: true, id: result.pid } }));
        setProbeSnifferResult({ status: "success", message: result.message });
        startPollingProbeSniffer();
      } else {
        setError("probeSniffer", result.error || "Failed to start probe sniffer");
      }
    } catch (error) {
      setProbeSnifferLoading(false);
      setError("probeSniffer", "Failed to start probe sniffer attack");
    }
  };

  const stopProbeSniffer = async () => {
    try {
      const response = await fetch('/api/probe-sniffer/stop', {
        method: 'POST'
      });
      
      const result = await response.json();
      
      if (!result.running) {
        setAttackStates(prev => ({ ...prev, probeSniffer: { running: false, id: null } }));
        setProbeSnifferResult({ status: "success", message: result.message });
        stopPollingProbeSniffer();
      } else {
        setError("probeSniffer", result.error || "Failed to stop probe sniffer");
      }
    } catch (error) {
      setError("probeSniffer", "Failed to stop probe sniffer attack");
    }
  };

  const startPollingProbeSniffer = () => {
    if (pollingIntervals.current.probeSniffer) {
      clearInterval(pollingIntervals.current.probeSniffer);
    }
    
    pollingIntervals.current.probeSniffer = setInterval(async () => {
      try {
        const response = await fetch('/api/probe-sniffer/logs?lines=10');
        const result = await response.json();
        setProbeSnifferLogs(result.logs || []);
      } catch (error) {
        console.error('Failed to fetch probe sniffer logs:', error);
      }
    }, 2000);
  };

  const stopPollingProbeSniffer = () => {
    if (pollingIntervals.current.probeSniffer) {
      clearInterval(pollingIntervals.current.probeSniffer);
      pollingIntervals.current.probeSniffer = null;
    }
  };

  // ==================== EFFECTS ====================

  useEffect(() => {
    checkAPIHealth()

    // Cleanup intervals on unmount
    return () => {
      Object.values(pollingIntervals.current).forEach((interval) => {
        if (interval) clearInterval(interval)
      })
    }
  }, [])

  // ==================== UTILITY FUNCTIONS ====================

  const addLog = (type, message) => {
    const timestamp = new Date().toLocaleTimeString()
    const logEntry = `[${timestamp}] ${message}`

    setLogs((prev) => ({
      ...prev,
      [type]: [...prev[type], logEntry].slice(-50), // Keep last 50 messages
    }))
  }

  const setError = (key, message) => {
    setErrors((prev) => ({ ...prev, [key]: message }))
    setTimeout(() => {
      setErrors((prev) => {
        const newErrors = { ...prev }
        delete newErrors[key]
        return newErrors
      })
    }, 5000)
  }

  const startPolling = (attackType, attackId, statusFunction, trafficFunction = null) => {
    // Clear existing interval
    if (pollingIntervals.current[attackType]) {
      clearInterval(pollingIntervals.current[attackType])
    }

    // Start new polling
    pollingIntervals.current[attackType] = setInterval(async () => {
      try {
        const statusResult = await statusFunction(attackId)
        if (statusResult.success) {
          const stats = statusResult.data.stats

          // Update logs based on attack type
          if (attackType === "deauth") {
            addLog(
              "deauth",
              `📊 Packets: ${stats.packets_sent || 0} | Duration: ${stats.duration || 0}s | Clients: ${stats.clients_discovered || 0}`,
            )
          } else if (attackType === "icmp") {
            addLog(
              "icmp",
              `📊 Packets: ${stats.packets_sent || 0} | PPS: ${stats.packets_per_second?.toFixed(1) || 0} | Duration: ${stats.duration || 0}s`,
            )
          } else if (attackType === "mitm") {
            addLog(
              "mitm",
              `📊 Captured: ${stats.packets_captured || 0} | DNS: ${stats.dns_requests || 0} | HTTP: ${stats.http_requests || 0}`,
            )

            // Get traffic data for MITM
            if (trafficFunction) {
              const trafficResult = await trafficFunction(attackId)
              if (trafficResult.success) {
                setMitmTraffic(trafficResult.data.traffic || [])
              }
            }
          } else if (attackType === "handshake") {
            addLog(
              "handshake",
              `📊 EAPOL: ${stats.eapol_packets || 0} | Status: ${stats.status || 'running'} | Duration: ${stats.duration || 0}s`,
            )
            
            // Log special events
            if (stats.handshake_captured && !stats.handshake_captured_logged) {
              addLog("handshake", "🎯 4-way handshake captured! Starting password cracking...")
              stats.handshake_captured_logged = true
            }
            
            if (stats.password_found && !stats.password_found_logged) {
              addLog("handshake", `🔓 Password found: ${stats.password_found}`)
              stats.password_found_logged = true
            }
          }

          // Check if attack is still running
          if (stats.status !== 'running' && !stats.running) {
            clearInterval(pollingIntervals.current[attackType])
            setAttackStates((prev) => ({
              ...prev,
              [attackType]: { running: false, id: null },
            }))
            addLog(attackType, "Attack stopped")
          }
        }
      } catch (error) {
        console.error(`Polling error for ${attackType}:`, error)
      }
    }, 3000) // Poll every 3 seconds
  }

  const stopPolling = (attackType) => {
    if (pollingIntervals.current[attackType]) {
      clearInterval(pollingIntervals.current[attackType])
      pollingIntervals.current[attackType] = null
    }
  }

  // ==================== API FUNCTIONS ====================

  const checkAPIHealth = async () => {
    const result = await api.current.checkHealth()
    if (result.success) {
      setApiStatus({
        status: result.data.status,
        attacks: result.data.active_attacks,
      })
    } else {
      setError("api", "Failed to connect to backend server")
    }
  }

  const scanAccessPoints = async () => {
    setLoading((prev) => ({ ...prev, scan: true }))
    setErrors((prev) => {
      const newErrors = { ...prev }
      delete newErrors.scan
      return newErrors
    })

    const result = await api.current.scanAccessPoints(scanConfig.interface, scanConfig.duration, scanConfig.advanced)

    setLoading((prev) => ({ ...prev, scan: false }))

    if (result.success) {
      setAccessPoints(result.data.access_points)
      addLog("deauth", `Found ${result.data.access_points.length} access points`)
    } else {
      setError("scan", `Scan failed: ${result.error}`)
      addLog("deauth", `Scan failed: ${result.error}`)
    }
  }

  const discoverClients = async () => {
    setLoading((prev) => ({ ...prev, discover: true }))
    setErrors((prev) => {
      const newErrors = { ...prev }
      delete newErrors.discover
      return newErrors
    })

    const result = await api.current.discoverClients(scanConfig.interface)

    setLoading((prev) => ({ ...prev, discover: false }))

    if (result.success) {
      setNetworkClients(result.data.clients)
      addLog("icmp", `Found ${result.data.clients.length} network clients`)
    } else {
      setError("discover", `Discovery failed: ${result.error}`)
      addLog("icmp", `Discovery failed: ${result.error}`)
    }
  }

  const discoverMITMClients = async () => {
    setLoading((prev) => ({ ...prev, mitmDiscover: true }))
    setErrors((prev) => {
      const newErrors = { ...prev }
      delete newErrors.mitmDiscover
      return newErrors
    })

    const result = await api.current.discoverMITMClients(mitmConfig.interface)

    setLoading((prev) => ({ ...prev, mitmDiscover: false }))

    if (result.success) {
      setMitmClients(result.data.clients)
      addLog("mitm", `Found ${result.data.clients.length} network clients`)
      if (result.data.network_info) {
        addLog(
          "mitm",
          `Network: ${result.data.network_info.network_range} | Gateway: ${result.data.network_info.gateway_ip}`,
        )
      }
    } else {
      setError("mitmDiscover", `MITM Discovery failed: ${result.error}`)
      addLog("mitm", `MITM Discovery failed: ${result.error}`)
    }
  }

  // ==================== DEAUTH ATTACK FUNCTIONS ====================

  const startDeauthAttack = async () => {
    if (!deauthConfig.ssid || !deauthConfig.bssid) {
      setError("deauth", "Please fill in SSID and BSSID")
      return
    }

    const result = await api.current.startDeauthAttack(
      deauthConfig.interface,
      deauthConfig.ssid,
      deauthConfig.bssid,
      deauthConfig.channel,
    )

    if (result.success) {
      const attackId = result.data.attack_id
      setAttackStates((prev) => ({
        ...prev,
        deauth: { running: true, id: attackId },
      }))
      addLog("deauth", `Attack started on ${deauthConfig.ssid} (${deauthConfig.bssid})`)

      // Start polling for status
      startPolling("deauth", attackId, api.current.getDeauthStatus.bind(api.current))
    } else {
      setError("deauth", `Attack failed: ${result.error}`)
    }
  }

  const stopDeauthAttack = async () => {
    if (attackStates.deauth.id) {
      const result = await api.current.stopDeauthAttack(attackStates.deauth.id)
      if (result.success) {
        stopPolling("deauth")
        setAttackStates((prev) => ({
          ...prev,
          deauth: { running: false, id: null },
        }))
        addLog("deauth", "Attack stopped by user")
      }
    }
  }

  // ==================== ICMP ATTACK FUNCTIONS ====================

  const startICMPAttack = async () => {
    if (!icmpConfig.targetIP) {
      setError("icmp", "Please enter target IP address")
      return
    }

    const result = await api.current.startICMPFlood(
      icmpConfig.interface,
      icmpConfig.targetIP,
      icmpConfig.packetSize,
      icmpConfig.delay,
    )

    if (result.success) {
      const attackId = result.data.attack_id
      setAttackStates((prev) => ({
        ...prev,
        icmp: { running: true, id: attackId },
      }))
      addLog("icmp", `ICMP flood started on ${icmpConfig.targetIP}`)

      // Start polling for status
      startPolling("icmp", attackId, api.current.getICMPStatus.bind(api.current))
    } else {
      setError("icmp", `Attack failed: ${result.error}`)
    }
  }

  const stopICMPAttack = async () => {
    if (attackStates.icmp.id) {
      const result = await api.current.stopICMPFlood(attackStates.icmp.id)
      if (result.success) {
        stopPolling("icmp")
        setAttackStates((prev) => ({
          ...prev,
          icmp: { running: false, id: null },
        }))
        addLog("icmp", "Attack stopped by user")
      }
    }
  }

  // ==================== MITM ATTACK FUNCTIONS ====================

  const startMITMAttack = async () => {
    if (mitmConfig.selectedTargets.length === 0) {
      setError("mitm", "Please select at least one target")
      return
    }

    const result = await api.current.startMITMAttack(mitmConfig.interface, mitmConfig.selectedTargets)

    if (result.success) {
      const attackId = result.data.attack_id
      setAttackStates((prev) => ({
        ...prev,
        mitm: { running: true, id: attackId },
      }))
      addLog("mitm", `MITM attack started on ${mitmConfig.selectedTargets.length} targets`)

      // Start polling for status and traffic
      startPolling(
        "mitm",
        attackId,
        api.current.getMITMStatus.bind(api.current),
        api.current.getMITMTraffic.bind(api.current),
      )
    } else {
      setError("mitm", `Attack failed: ${result.error}`)
    }
  }

  const stopMITMAttack = async () => {
    if (attackStates.mitm.id) {
      const result = await api.current.stopMITMAttack(attackStates.mitm.id)
      if (result.success) {
        stopPolling("mitm")
        setAttackStates((prev) => ({
          ...prev,
          mitm: { running: false, id: null },
        }))
        addLog("mitm", "Attack stopped by user")
        setMitmTraffic([])
      }
    }
  }

  // ==================== HANDSHAKE CAPTURE ATTACK FUNCTIONS ====================

  const startHandshakeCapture = async () => {
    if (!handshakeConfig.ssid || !handshakeConfig.bssid) {
      setError("handshake", "Please fill in SSID and BSSID")
      return
    }

    const result = await api.current.startHandshakeCapture(
      handshakeConfig.interface,
      handshakeConfig.ssid,
      handshakeConfig.bssid,
      handshakeConfig.channel,
      handshakeConfig.wordlist,
      handshakeConfig.timeout,
      handshakeConfig.deauthCount,
      handshakeConfig.deauthInterval
    )

    if (result.success) {
      const attackId = result.data.attack_id
      setAttackStates((prev) => ({
        ...prev,
        handshake: { running: true, id: attackId },
      }))
      addLog("handshake", `Handshake capture started on ${handshakeConfig.ssid} (${handshakeConfig.bssid})`)

      // Start polling for status
      startPolling("handshake", attackId, api.current.getHandshakeCaptureStatus.bind(api.current))
    } else {
      setError("handshake", `Attack failed: ${result.error}`)
    }
  }

  const stopHandshakeCapture = async () => {
    if (attackStates.handshake.id) {
      const result = await api.current.stopHandshakeCapture(attackStates.handshake.id)
      if (result.success) {
        stopPolling("handshake")
        setAttackStates((prev) => ({
          ...prev,
          handshake: { running: false, id: null },
        }))
        addLog("handshake", "Attack stopped by user")
      }
    }
  }

  // ==================== HELPER FUNCTIONS ====================

  const selectAP = (ap) => {
    setDeauthConfig((prev) => ({
      ...prev,
      ssid: ap.ssid || "Hidden_Network",
      bssid: ap.bssid,
      channel: Number.parseInt(ap.channel) || 6,
    }))
    setHandshakeConfig((prev) => ({
      ...prev,
      ssid: ap.ssid || "Hidden_Network",
      bssid: ap.bssid,
      channel: Number.parseInt(ap.channel) || 6,
    }))
    addLog("deauth", `Selected AP: ${ap.ssid} (${ap.bssid})`)
    addLog("handshake", `Selected AP: ${ap.ssid} (${ap.bssid})`)
  }

  const selectClient = (client) => {
    setIcmpConfig((prev) => ({
      ...prev,
      targetIP: client.ip,
    }))
    addLog("icmp", `Selected target: ${client.ip}`)
  }

  const toggleMITMTarget = (client) => {
    setMitmConfig((prev) => {
      const isSelected = prev.selectedTargets.includes(client.ip)
      const newTargets = isSelected
        ? prev.selectedTargets.filter((ip) => ip !== client.ip)
        : [...prev.selectedTargets, client.ip]

      return {
        ...prev,
        selectedTargets: newTargets,
      }
    })
  }

  const stopAllAttacks = async () => {
    // Stop all local polling
    Object.keys(pollingIntervals.current).forEach((attackType) => {
      stopPolling(attackType)
    })

    // Stop probe sniffer specifically
    stopPollingProbeSniffer()

    // Stop all attacks on server
    const result = await api.current.stopAllAttacks()
    if (result.success) {
      setAttackStates({
        deauth: { running: false, id: null },
        icmp: { running: false, id: null },
        mitm: { running: false, id: null },
        handshake: { running: false, id: null },
        probeSniffer: { running: false, id: null },
      })
      setMitmTraffic([])
      setProbeSnifferLogs([])
      addLog("deauth", "All attacks stopped")
      addLog("icmp", "All attacks stopped")
      addLog("mitm", "All attacks stopped")
      addLog("handshake", "All attacks stopped")
    }
  }

  // ==================== RENDER ====================

  if (showEvilTwin) {
    return (
      <div style={{ padding: 24 }}>
        <button
          onClick={() => setShowEvilTwin(false)}
          style={{ marginBottom: 16, padding: '8px 16px', background: '#374151', color: 'white', borderRadius: 6, border: 'none', fontWeight: 600 }}
        >
          ← Back to Dashboard
        </button>
        <EvilTwinAttack />
      </div>
    );
  }

  if (showWiFiBlocker) {
    return (
      <div style={{ padding: 24 }}>
        <button
          onClick={() => setShowWiFiBlocker(false)}
          style={{ marginBottom: 16, padding: '8px 16px', background: '#374151', color: 'white', borderRadius: 6, border: 'none', fontWeight: 600 }}
        >
          ← Back to Dashboard
        </button>
        <WiFiBlockerAttack />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-red-500 mr-3" />
              <h1 className="text-xl font-bold">Airstrike Control Panel</h1>
            </div>
            <div className="flex items-center space-x-4">
              <div
                className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm ${
                  apiStatus.status === "healthy" ? "bg-green-900 text-green-300" : "bg-red-900 text-red-300"
                }`}
              >
                <Activity className="h-4 w-4" />
                <span>{apiStatus.status}</span>
                <span>•</span>
                <span>{apiStatus.attacks} active</span>
              </div>
              <button onClick={checkAPIHealth} className="p-2 text-gray-400 hover:text-white transition-colors">
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Display */}
        {Object.entries(errors).map(([key, error]) => (
          <div key={key} className="mb-4 bg-red-900 border border-red-700 text-red-300 px-4 py-3 rounded">
            <div className="flex items-center">
              <AlertTriangle className="h-4 w-4 mr-2" />
              <span>{error}</span>
            </div>
          </div>
        ))}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Configuration */}
          <div className="space-y-8">
            {/* Interface Configuration */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Wifi className="h-5 w-5 mr-2" />
                Interface Configuration
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Network Interface</label>
                  <input
                    type="text"
                    value={scanConfig.interface}
                    onChange={(e) => {
                      setScanConfig((prev) => ({ ...prev, interface: e.target.value }))
                      setMitmConfig((prev) => ({ ...prev, interface: e.target.value }))
                      setHandshakeConfig((prev) => ({ ...prev, interface: e.target.value }))
                      setProbeSnifferConfig((prev) => ({ ...prev, interface: e.target.value }))
                    }}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="e.g., wlan0"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Scan Duration (s)</label>
                    <input
                      type="number"
                      value={scanConfig.duration}
                      onChange={(e) =>
                        setScanConfig((prev) => ({ ...prev, duration: Number.parseInt(e.target.value) }))
                      }
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                      min="5"
                      max="300"
                    />
                  </div>
                  <div className="flex items-end">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={scanConfig.advanced}
                        onChange={(e) => setScanConfig((prev) => ({ ...prev, advanced: e.target.checked }))}
                        className="mr-2"
                      />
                      <span className="text-sm text-gray-300">Advanced Scan</span>
                    </label>
                  </div>
                </div>
              </div>
            </div>

            {/* Access Point Scanning */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Search className="h-5 w-5 mr-2" />
                Access Point Discovery
              </h2>
              <button
                onClick={scanAccessPoints}
                disabled={loading.scan}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
              >
                {loading.scan ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-2" />
                    Scan Access Points
                  </>
                )}
              </button>

              {accessPoints.length > 0 && (
                <div className="mt-4">
                  <h3 className="text-sm font-medium text-gray-300 mb-2">Found {accessPoints.length} Access Points:</h3>
                  <div className="max-h-64 overflow-y-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-gray-400 border-b border-gray-700">
                          <th className="text-left py-2">SSID</th>
                          <th className="text-left py-2">Channel</th>
                          <th className="text-left py-2">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {accessPoints.map((ap, index) => (
                          <tr key={index} className="border-b border-gray-700">
                            <td className="py-2 truncate max-w-32" title={ap.ssid || "Hidden"}>
                              {ap.ssid || "Hidden"}
                            </td>
                            <td className="py-2">{ap.channel}</td>
                            <td className="py-2">
                              <button
                                onClick={() => selectAP(ap)}
                                className="text-blue-400 hover:text-blue-300 text-xs"
                              >
                                Select
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
                        {/* Kill Adapter Processes & Restart Network Manager Box */}
<div className="bg-gray-800 rounded-lg p-6 mt-6 flex flex-col items-center">
  <h2 className="text-lg font-semibold mb-4 flex items-center">
    {/* You can add an emoji if you want: <span className="mr-2">🛡️</span> */}
    Network Adapter Actions
  </h2>
  <button
    onClick={handleNetworkAction}
    disabled={networkActionLoading}
    className="w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-md font-semibold text-base shadow-md transition-all duration-150"
    style={{ marginTop: 8 }}
  >
    {networkActionLoading ? "Processing..." : "Kill Adapter Processes & Restart Network Manager"}
  </button>
  {networkActionResult && (
    <div className="mt-3 text-sm text-center w-full">
      {networkActionResult.actions && networkActionResult.actions.length > 0 && (
        <div className="text-green-500">{networkActionResult.actions.join('; ')}</div>
      )}
      {networkActionResult.errors && networkActionResult.errors.length > 0 && (
        <div className="text-red-600">{networkActionResult.errors.join('; ')}</div>
      )}
    </div>
  )}
  
  {/* Wireless Interface Reset Button */}
  <button
    onClick={handleWirelessReset}
    disabled={wirelessResetLoading}
    className="w-full px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-md font-semibold text-base shadow-md transition-all duration-150 mt-4"
  >
    {wirelessResetLoading ? "Processing..." : "Reset Wireless Interface to Managed Mode"}
  </button>
  {wirelessResetResult && (
    <div className="mt-3 text-sm text-center w-full">
      {wirelessResetResult.actions && wirelessResetResult.actions.length > 0 && (
        <div className="text-green-500">{wirelessResetResult.actions.join('; ')}</div>
      )}
      {wirelessResetResult.errors && wirelessResetResult.errors.length > 0 && (
        <div className="text-red-600">{wirelessResetResult.errors.join('; ')}</div>
      )}
    </div>
  )}
</div>

            {/* Client Discovery */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Users className="h-5 w-5 mr-2" />
                Network Client Discovery
              </h2>
              <div className="space-y-2">
                <button
                  onClick={discoverClients}
                  disabled={loading.discover}
                  className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
                >
                  {loading.discover ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Discovering...
                    </>
                  ) : (
                    <>
                      <Users className="h-4 w-4 mr-2" />
                      Discover ICMP Clients
                    </>
                  )}
                </button>

                <button
                  onClick={discoverMITMClients}
                  disabled={loading.mitmDiscover}
                  className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
                >
                  {loading.mitmDiscover ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Discovering...
                    </>
                  ) : (
                    <>
                      <Eye className="h-4 w-4 mr-2" />
                      Discover MITM Clients
                    </>
                  )}
                </button>
              </div>

              {networkClients.length > 0 && (
                <div className="mt-4">
                  <h3 className="text-sm font-medium text-gray-300 mb-2">ICMP Clients ({networkClients.length}):</h3>
                  <div className="max-h-32 overflow-y-auto">
                    <table className="w-full text-sm">
                      <tbody>
                        {networkClients.map((client, index) => (
                          <tr key={index} className="border-b border-gray-700">
                            <td className="py-1">{client.ip}</td>
                            <td className="py-1">
                              <button
                                onClick={() => selectClient(client)}
                                className="text-blue-400 hover:text-blue-300 text-xs"
                              >
                                Select
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {mitmClients.length > 0 && (
                <div className="mt-4">
                  <h3 className="text-sm font-medium text-gray-300 mb-2">
                    MITM Clients ({mitmClients.length}) - Selected: {mitmConfig.selectedTargets.length}
                  </h3>
                  <div className="max-h-32 overflow-y-auto">
                    <table className="w-full text-sm">
                      <tbody>
                        {mitmClients.map((client, index) => (
                          <tr key={index} className="border-b border-gray-700">
                            <td className="py-1">{client.ip}</td>
                            <td className="py-1 text-xs text-gray-400">{client.hostname}</td>
                            <td className="py-1">
                              <button
                                onClick={() => toggleMITMTarget(client)}
                                className={`text-xs px-2 py-1 rounded ${
                                  mitmConfig.selectedTargets.includes(client.ip)
                                    ? "bg-purple-600 text-white"
                                    : "bg-gray-600 text-gray-300 hover:bg-gray-500"
                                }`}
                              >
                                {mitmConfig.selectedTargets.includes(client.ip) ? "Selected" : "Select"}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>

            {/* Handshake Capture Attack */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Shield className="h-5 w-5 mr-2 text-orange-500" />
                Handshake Capture Attack
              </h2>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">SSID</label>
                    <input
                      type="text"
                      value={handshakeConfig.ssid}
                      onChange={(e) => setHandshakeConfig((prev) => ({ ...prev, ssid: e.target.value }))}
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                      placeholder="Network name"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Channel</label>
                    <input
                      type="number"
                      value={handshakeConfig.channel}
                      onChange={(e) =>
                        setHandshakeConfig((prev) => ({ ...prev, channel: Number.parseInt(e.target.value) }))
                      }
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                      min="1"
                      max="14"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">BSSID (MAC Address)</label>
                  <input
                    type="text"
                    value={handshakeConfig.bssid}
                    onChange={(e) => setHandshakeConfig((prev) => ({ ...prev, bssid: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                    placeholder="aa:bb:cc:dd:ee:ff"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Wordlist Path</label>
                  <input
                    type="text"
                    value={handshakeConfig.wordlist}
                    onChange={(e) => setHandshakeConfig((prev) => ({ ...prev, wordlist: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                    placeholder="/usr/share/wordlists/rockyou.txt"
                  />
                </div>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Timeout (s)</label>
                    <input
                      type="number"
                      value={handshakeConfig.timeout}
                      onChange={(e) =>
                        setHandshakeConfig((prev) => ({ ...prev, timeout: Number.parseInt(e.target.value) }))
                      }
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                      min="30"
                      max="300"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Deauth Count</label>
                    <input
                      type="number"
                      value={handshakeConfig.deauthCount}
                      onChange={(e) =>
                        setHandshakeConfig((prev) => ({ ...prev, deauthCount: Number.parseInt(e.target.value) }))
                      }
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                      min="1"
                      max="20"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Deauth Interval (s)</label>
                    <input
                      type="number"
                      step="0.1"
                      value={handshakeConfig.deauthInterval}
                      onChange={(e) =>
                        setHandshakeConfig((prev) => ({ ...prev, deauthInterval: Number.parseFloat(e.target.value) }))
                      }
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                      min="0.5"
                      max="10.0"
                    />
                  </div>
                </div>

                <div className="flex space-x-2">
                  <button
                    onClick={startHandshakeCapture}
                    disabled={attackStates.handshake.running}
                    className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
                  >
                    {attackStates.handshake.running ? (
                      <>
                        <Square className="h-4 w-4 mr-2" />
                        Attack Running
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Start Attack
                      </>
                    )}
                  </button>
                  <button
                    onClick={stopHandshakeCapture}
                    disabled={!attackStates.handshake.running}
                    className="bg-gray-600 hover:bg-gray-700 disabled:bg-gray-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
                  >
                    <Square className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Handshake Logs */}
              <div className="mt-4">
                <h3 className="text-sm font-medium text-gray-300 mb-2">Real-time Updates:</h3>
                <div className="bg-gray-900 rounded-md p-3 h-24 overflow-y-auto text-xs font-mono">
                  {logs.handshake.map((log, index) => (
                    <div key={index} className="text-gray-300">
                      {log}
                    </div>
                  ))}
                  {logs.handshake.length === 0 && <div className="text-gray-500">No activity yet...</div>}
                </div>
              </div>
            </div>
          </div>

          {/* Middle Column - Attacks */}
          <div className="space-y-8">
            
            {/* Probe Request Sniffer Attack */}
            <div className="bg-gray-800 rounded-lg p-6" onMouseEnter={() => setProbeSnifferSectionActive(true)}>
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Eye className="h-5 w-5 mr-2 text-purple-400" />
                Probe Request Sniffer
              </h2>
              <div className="space-y-4">
                {/* Show summary and refresh button only when section is active */}
                {probeSnifferSectionActive && (
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-purple-300">{probeSnifferSummary}</span>
                    <button
                      onClick={fetchProbeSnifferStats}
                      className="ml-2 px-2 py-1 text-xs bg-gray-700 text-white rounded hover:bg-purple-700"
                    >
                      Refresh
                    </button>
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Interface</label>
                  <input
                    type="text"
                    value={probeSnifferConfig.interface}
                    onChange={e => setProbeSnifferConfig(prev => ({ ...prev, interface: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder="e.g., wlan0"
                  />
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={startProbeSniffer}
                    disabled={attackStates.probeSniffer.running || probeSnifferLoading}
                    className="flex-1 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
                  >
                    {probeSnifferLoading ? (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        Starting...
                      </>
                    ) : attackStates.probeSniffer.running ? (
                      <>
                        <Square className="h-4 w-4 mr-2" />
                        Attack Running
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Start Sniffer
                      </>
                    )}
                  </button>
                  <button
                    onClick={stopProbeSniffer}
                    disabled={!attackStates.probeSniffer.running}
                    className="bg-gray-600 hover:bg-gray-700 disabled:bg-gray-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
                  >
                    <Square className="h-4 w-4" />
                  </button>
                </div>
                {probeSnifferResult && (
                  <div className="mt-2 text-sm">
                    {probeSnifferResult.status === "success" && (
                      <div className="text-green-500">{probeSnifferResult.message}</div>
                    )}
                    {probeSnifferResult.status === "error" && (
                      <div className="text-red-600">{probeSnifferResult.message}</div>
                    )}
                  </div>
                )}
                {/* Probe Sniffer Logs */}
                <div className="mt-4">
                  <h3 className="text-sm font-medium text-gray-300 mb-2">Live Probe Detection:</h3>
                  <div className="bg-gray-900 rounded-md p-3 h-32 overflow-y-auto text-xs font-mono">
                    {probeSnifferLogs.map((log, index) => (
                      <div key={index} className="text-gray-300 mb-1">
                        {log}
                      </div>
                    ))}
                    {probeSnifferLogs.length === 0 && <div className="text-gray-500">No probes detected yet...</div>}
                  </div>
                </div>
              </div>
            </div>
            {/* Deauth Attack */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Zap className="h-5 w-5 mr-2 text-yellow-500" />
                Deauthentication Attack
              </h2>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">SSID</label>
                    <input
                      type="text"
                      value={deauthConfig.ssid}
                      onChange={(e) => setDeauthConfig((prev) => ({ ...prev, ssid: e.target.value }))}
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-yellow-500"
                      placeholder="Network name"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Channel</label>
                    <input
                      type="number"
                      value={deauthConfig.channel}
                      onChange={(e) =>
                        setDeauthConfig((prev) => ({ ...prev, channel: Number.parseInt(e.target.value) }))
                      }
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-yellow-500"
                      min="1"
                      max="14"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">BSSID (MAC Address)</label>
                  <input
                    type="text"
                    value={deauthConfig.bssid}
                    onChange={(e) => setDeauthConfig((prev) => ({ ...prev, bssid: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-yellow-500"
                    placeholder="aa:bb:cc:dd:ee:ff"
                  />
                </div>

                <div className="flex space-x-2">
                  <button
                    onClick={startDeauthAttack}
                    disabled={attackStates.deauth.running}
                    className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
                  >
                    {attackStates.deauth.running ? (
                      <>
                        <Square className="h-4 w-4 mr-2" />
                        Attack Running
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Start Attack
                      </>
                    )}
                  </button>
                  <button
                    onClick={stopDeauthAttack}
                    disabled={!attackStates.deauth.running}
                    className="bg-gray-600 hover:bg-gray-700 disabled:bg-gray-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
                  >
                    <Square className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Deauth Logs */}
              <div className="mt-4">
                <h3 className="text-sm font-medium text-gray-300 mb-2">Real-time Updates:</h3>
                <div className="bg-gray-900 rounded-md p-3 h-24 overflow-y-auto text-xs font-mono">
                  {logs.deauth.map((log, index) => (
                    <div key={index} className="text-gray-300">
                      {log}
                    </div>
                  ))}
                  {logs.deauth.length === 0 && <div className="text-gray-500">No activity yet...</div>}
                </div>
              </div>
            </div>

            {/* ICMP Flood Attack */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Waves className="h-5 w-5 mr-2 text-blue-500" />
                ICMP Flood Attack
              </h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Target IP Address</label>
                  <input
                    type="text"
                    value={icmpConfig.targetIP}
                    onChange={(e) => setIcmpConfig((prev) => ({ ...prev, targetIP: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="192.168.1.100"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Packet Size</label>
                    <input
                      type="number"
                      value={icmpConfig.packetSize}
                      onChange={(e) =>
                        setIcmpConfig((prev) => ({ ...prev, packetSize: Number.parseInt(e.target.value) }))
                      }
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                      min="28"
                      max="1500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Delay (s)</label>
                    <input
                      type="number"
                      step="0.001"
                      value={icmpConfig.delay}
                      onChange={(e) => setIcmpConfig((prev) => ({ ...prev, delay: Number.parseFloat(e.target.value) }))}
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                      min="0"
                    />
                  </div>
                </div>

                <div className="flex space-x-2">
                  <button
                    onClick={startICMPAttack}
                    disabled={attackStates.icmp.running}
                    className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
                  >
                    {attackStates.icmp.running ? (
                      <>
                        <Square className="h-4 w-4 mr-2" />
                        Attack Running
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Start Attack
                      </>
                    )}
                  </button>
                  <button
                    onClick={stopICMPAttack}
                    disabled={!attackStates.icmp.running}
                    className="bg-gray-600 hover:bg-gray-700 disabled:bg-gray-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
                  >
                    <Square className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* ICMP Logs */}
              <div className="mt-4">
                <h3 className="text-sm font-medium text-gray-300 mb-2">Real-time Updates:</h3>
                <div className="bg-gray-900 rounded-md p-3 h-24 overflow-y-auto text-xs font-mono">
                  {logs.icmp.map((log, index) => (
                    <div key={index} className="text-gray-300">
                      {log}
                    </div>
                  ))}
                  {logs.icmp.length === 0 && <div className="text-gray-500">No activity yet...</div>}
                </div>
              </div>
            </div>


          </div>

          {/* Right Column - Traffic & Controls */}



          <div className="space-y-8">


            

            {/* Attack Status Summary */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Activity className="h-5 w-5 mr-2" />
                Attack Status
              </h2>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-300">Deauth Attack</span>
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      attackStates.deauth.running ? "bg-red-900 text-red-300" : "bg-gray-700 text-gray-400"
                    }`}
                  >
                    {attackStates.deauth.running ? "RUNNING" : "STOPPED"}
                  </span>
                  {attackStates.deauth.running && (
                    <button
                      onClick={stopDeauthAttack}
                      className="ml-2 px-2 py-1 text-xs bg-gray-700 text-white rounded hover:bg-red-700"
                    >
                      Stop
                    </button>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-300">ICMP Flood</span>
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      attackStates.icmp.running ? "bg-red-900 text-red-300" : "bg-gray-700 text-gray-400"
                    }`}
                  >
                    {attackStates.icmp.running ? "RUNNING" : "STOPPED"}
                  </span>
                  {attackStates.icmp.running && (
                    <button
                      onClick={stopICMPAttack}
                      className="ml-2 px-2 py-1 text-xs bg-gray-700 text-white rounded hover:bg-red-700"
                    >
                      Stop
                    </button>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-300">MITM Attack</span>
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      attackStates.mitm.running ? "bg-red-900 text-red-300" : "bg-gray-700 text-gray-400"
                    }`}
                  >
                    {attackStates.mitm.running ? "RUNNING" : "STOPPED"}
                  </span>
                  {attackStates.mitm.running && (
                    <button
                      onClick={stopMITMAttack}
                      className="ml-2 px-2 py-1 text-xs bg-gray-700 text-white rounded hover:bg-red-700"
                    >
                      Stop
                    </button>
                  )}
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-300">Handshake Capture</span>
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      attackStates.handshake.running ? "bg-red-900 text-red-300" : "bg-gray-700 text-gray-400"
                    }`}
                  >
                    {attackStates.handshake.running ? "RUNNING" : "STOPPED"}
                  </span>
                  {attackStates.handshake.running && (
                    <button
                      onClick={stopHandshakeCapture}
                      className="ml-2 px-2 py-1 text-xs bg-gray-700 text-white rounded hover:bg-red-700"
                    >
                      Stop
                    </button>
                  )}
                </div>
                {/* Probe Request Sniffer Attack Status */}
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-300">Probe Request Sniffer</span>
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      attackStates.probeSniffer.running ? "bg-purple-900 text-purple-300" : "bg-gray-700 text-gray-400"
                    }`}
                  >
                    {attackStates.probeSniffer.running ? "RUNNING" : "STOPPED"}
                  </span>
                  {attackStates.probeSniffer.running && (
                    <button
                      onClick={stopProbeSniffer}
                      className="ml-2 px-2 py-1 text-xs bg-gray-700 text-white rounded hover:bg-purple-700"
                    >
                      Stop
                    </button>
                  )}
                </div>
              </div>
            </div>
{/* Emergency Stop */}
<div className="bg-red-900 border border-red-700 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center text-red-300">
                <AlertTriangle className="h-5 w-5 mr-2" />
                Emergency Controls
              </h2>
              <button
                onClick={stopAllAttacks}
                className="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-3 px-4 rounded-md transition-colors flex items-center justify-center"
              >
                <Square className="h-4 w-4 mr-2" />
                STOP ALL ATTACKS
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection:"column", gap:"1rem", justifyContent: 'center', margin: '32px 0' }}>
        <button
          onClick={() => setShowEvilTwin(true)}
          style={{
            padding: '16px 32px',
            background: '#3b82f6',
            color: 'white',
            border: 'none',
            borderRadius: 8,
            fontSize: 20,
            fontWeight: 700,
            boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
            cursor: 'pointer',
            transition: 'background 0.2s'
          }}
        >
          Evil Twin Attack
        </button>
        <button
          onClick={() => setShowWiFiBlocker(true)}
          style={{
            padding: '16px 32px',
            background: '#3b82f6',
            color: 'white',
            border: 'none',
            borderRadius: 8,
            fontSize: 20,
            fontWeight: 700,
            boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
            cursor: 'pointer',
            transition: 'background 0.2s',
          }}
        >
          Wi-Fi Blocker Attack
        </button>
      </div>

            {/* MITM Attack */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Eye className="h-5 w-5 mr-2 text-purple-500" />
                Man-in-the-Middle Attack
              </h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Selected Targets ({mitmConfig.selectedTargets.length})
                  </label>
                  <div className="bg-gray-700 rounded-md p-2 min-h-16 max-h-20 overflow-y-auto">
                    {mitmConfig.selectedTargets.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {mitmConfig.selectedTargets.map((ip, index) => (
                          <span key={index} className="bg-purple-600 text-white px-2 py-1 rounded text-xs">
                            {ip}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <div className="text-gray-400 text-sm">No targets selected</div>
                    )}
                  </div>
                </div>

                <div className="flex space-x-2">
                  <button
                    onClick={startMITMAttack}
                    disabled={attackStates.mitm.running}
                    className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
                  >
                    {attackStates.mitm.running ? (
                      <>
                        <Square className="h-4 w-4 mr-2" />
                        Attack Running
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Start MITM
                      </>
                    )}
                  </button>
                  <button
                    onClick={stopMITMAttack}
                    disabled={!attackStates.mitm.running}
                    className="bg-gray-600 hover:bg-gray-700 disabled:bg-gray-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
                  >
                    <Square className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* MITM Logs */}
              <div className="mt-4">
                <h3 className="text-sm font-medium text-gray-300 mb-2">Real-time Updates:</h3>
                <div className="bg-gray-900 rounded-md p-3 h-24 overflow-y-auto text-xs font-mono">
                  {logs.mitm.map((log, index) => (
                    <div key={index} className="text-gray-300">
                      {log}
                    </div>
                  ))}
                  {logs.mitm.length === 0 && <div className="text-gray-500">No activity yet...</div>}
                </div>
              </div>
            </div>

            {/* Captured Traffic */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center">
                <Globe className="h-5 w-5 mr-2 text-green-500" />
                Captured Traffic
              </h2>

              <div className="bg-gray-900 rounded-md p-3 h-80 overflow-y-auto">
                {mitmTraffic.length > 0 ? (
                  <div className="space-y-2">
                    {mitmTraffic.map((traffic, index) => (
                      <div key={index} className="border-b border-gray-700 pb-2">
                        <div className="flex items-center justify-between">
                          <span
                            className={`text-xs px-2 py-1 rounded ${
                              traffic.type === "DNS" ? "bg-blue-900 text-blue-300" : "bg-green-900 text-green-300"
                            }`}
                          >
                            {traffic.type}
                          </span>
                          <span className="text-xs text-gray-400">{traffic.timestamp}</span>
                        </div>
                        <div className="text-sm text-gray-300 mt-1">
                          <div className="text-xs text-gray-400">From: {traffic.source_ip}</div>
                          <div className={traffic.credentials ? "text-red-300 font-bold" : ""}>{traffic.details}</div>
                          {traffic.type === "HTTP" && (
                            <div className="text-xs text-gray-500">
                              {traffic.method} {traffic.host}
                              {traffic.path}
                            </div>
                          )}
                          {traffic.type === "DNS" && (
                            <div className="text-xs text-gray-500">Query: {traffic.domain}</div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-gray-500 text-center py-8">
                    {attackStates.mitm.running ? "Waiting for traffic..." : "Start MITM attack to capture traffic"}
                  </div>
                )}
              </div>
            </div>

          </div>
        </div>
      </div>
     
    </div>
  )
}

export default App
