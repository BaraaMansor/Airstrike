/**
 * Airstrike API Client - HTTP Only (No WebSocket)
 */

class AirstrikeAPI {
  constructor(baseURL = "http://localhost:8000") {
    this.baseURL = baseURL
  }

  // ==================== BASIC API ENDPOINTS ====================

  async checkHealth() {
    try {
      const response = await fetch(`${this.baseURL}/health`)
      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async getAPIInfo() {
    try {
      const response = await fetch(`${this.baseURL}/`)
      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  // ==================== ACCESS POINT SCANNING ====================

  async scanAccessPoints(wifiInterface, duration = 30, advanced = true) {
    try {
      const response = await fetch(`${this.baseURL}/scan/access-points`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          interface: wifiInterface,
          duration: duration,
          advanced: advanced,
        }),
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  // ==================== CLIENT DISCOVERY ====================

  async discoverClients(networkInterface) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/icmp-flood/discover`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          interface: networkInterface,
        }),
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  // ==================== MITM ATTACK ENDPOINTS ====================

  async discoverMITMClients(networkInterface) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/mitm/discover`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          interface: networkInterface,
          target_ips: [],
        }),
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async startMITMAttack(networkInterface, targetIPs) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/mitm/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          interface: networkInterface,
          target_ips: targetIPs,
        }),
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async stopMITMAttack(attackId) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/mitm/stop/${attackId}`, {
        method: "POST",
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async getMITMStatus(attackId) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/mitm/status/${attackId}`)
      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async getMITMTraffic(attackId, limit = 50) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/mitm/traffic/${attackId}?limit=${limit}`)
      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  // ==================== DEAUTH ATTACK HTTP ENDPOINTS ====================

  async startDeauthAttack(wifiInterface, ssid, bssid, channel) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/deauth/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          interface: wifiInterface,
          ssid: ssid,
          bssid: bssid,
          channel: channel,
        }),
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async stopDeauthAttack(attackId) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/deauth/stop/${attackId}`, {
        method: "POST",
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async getDeauthStatus(attackId) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/deauth/status/${attackId}`)
      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  // ==================== ICMP FLOOD HTTP ENDPOINTS ====================

  async startICMPFlood(networkInterface, targetIP, packetSize = 64, delay = 0.001) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/icmp-flood/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          interface: networkInterface,
          target_ip: targetIP,
          packet_size: packetSize,
          delay: delay,
        }),
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async stopICMPFlood(attackId) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/icmp-flood/stop/${attackId}`, {
        method: "POST",
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async getICMPStatus(attackId) {
    try {
      const response = await fetch(`${this.baseURL}/attacks/icmp-flood/status/${attackId}`)
      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  // ==================== ATTACK MANAGEMENT ====================

  async getActiveAttacks() {
    try {
      const response = await fetch(`${this.baseURL}/attacks/active`)
      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }

  async stopAllAttacks() {
    try {
      const response = await fetch(`${this.baseURL}/attacks/stop-all`, {
        method: "POST",
      })

      const data = await response.json()
      return {
        success: response.ok,
        data: data,
      }
    } catch (error) {
      return { success: false, error: error.message }
    }
  }
}

export default AirstrikeAPI
