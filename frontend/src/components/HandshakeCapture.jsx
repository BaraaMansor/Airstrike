import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Switch } from './ui/switch';
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { Alert, AlertDescription } from './ui/alert';
import { Separator } from './ui/separator';
import { 
    Wifi, 
    Target, 
    Play, 
    Square, 
    AlertCircle, 
    CheckCircle, 
    Clock, 
    FileText,
    Settings,
    Monitor,
    Shield,
    Key
} from 'lucide-react';
import { toast } from 'sonner';

const HandshakeCapture = () => {
    const [isRunning, setIsRunning] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [status, setStatus] = useState('idle');
    const [stats, setStats] = useState({});
    const [error, setError] = useState(null);
    const [logs, setLogs] = useState([]);
    
    // Form state
    const [interface, setInterface] = useState('');
    const [ssid, setSsid] = useState('');
    const [bssid, setBssid] = useState('');
    const [channel, setChannel] = useState('');
    const [wordlist, setWordlist] = useState('/usr/share/wordlists/rockyou.txt');
    const [timeout, setTimeout] = useState(60);
    const [deauthCount, setDeauthCount] = useState(5);
    const [deauthInterval, setDeauthInterval] = useState(2.0);
    const [outputDir, setOutputDir] = useState('/tmp/airstrike_captures');
    const [restoreManaged, setRestoreManaged] = useState(true);
    
    // Enhanced status tracking
    const [handshakeStatus, setHandshakeStatus] = useState('not_started');
    const [crackingStatus, setCrackingStatus] = useState('not_started');
    const [passwordFound, setPasswordFound] = useState(null);
    const [eapolMessages, setEapolMessages] = useState({});
    const [clientsDiscovered, setClientsDiscovered] = useState(0);
    const [packetsSent, setPacketsSent] = useState(0);
    const [eapolPackets, setEapolPackets] = useState(0);
    
    const wsRef = useRef(null);
    const statusIntervalRef = useRef(null);

    useEffect(() => {
        // Get available interfaces on component mount
        getInterfaces();
        
        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
            if (statusIntervalRef.current) {
                clearInterval(statusIntervalRef.current);
            }
        };
    }, []);

    const getInterfaces = async () => {
        try {
            const response = await fetch('/api/interfaces');
            const data = await response.json();
            if (data.interfaces && data.interfaces.length > 0) {
                setInterface(data.interfaces[0]);
            }
        } catch (error) {
            console.error('Error getting interfaces:', error);
        }
    };

    const connectWebSocket = () => {
        const ws = new WebSocket(`ws://${window.location.host}/ws`);
        
        ws.onopen = () => {
            console.log('WebSocket connected for handshake capture');
            wsRef.current = ws;
        };
        
        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                handleWebSocketMessage(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            setError('WebSocket connection failed');
        };
        
        ws.onclose = () => {
            console.log('WebSocket disconnected');
            wsRef.current = null;
        };
    };

    const handleWebSocketMessage = (message) => {
        const { type, data } = message;
        
        switch (type) {
            case 'attack_starting':
                addLog('info', `Starting handshake capture attack on ${data.ssid} (${data.bssid})`);
                break;
                
            case 'progress':
                setProgress(data.progress);
                addLog('info', data.message);
                break;
                
            case 'client_discovered':
                setClientsDiscovered(data.total_clients);
                addLog('success', `Client discovered: ${data.client_mac}`);
                break;
                
            case 'handshake_captured':
                setHandshakeStatus('captured');
                setEapolPackets(data.eapol_count);
                setEapolMessages(data.eapol_messages);
                addLog('success', data.message);
                toast.success('Handshake captured successfully!');
                break;
                
            case 'cracking_started':
                setCrackingStatus('cracking');
                addLog('info', data.message);
                break;
                
            case 'password_found':
                setCrackingStatus('success');
                setPasswordFound(data.password);
                addLog('success', data.message);
                toast.success(`Password found: ${data.password}`);
                break;
                
            case 'cracking_failed':
                setCrackingStatus('failed');
                addLog('warning', data.message);
                toast.error('Password not found in wordlist');
                break;
                
            case 'cracking_timeout':
                setCrackingStatus('timeout');
                addLog('warning', data.message);
                toast.error('Password cracking timed out');
                break;
                
            case 'cracking_error':
                setCrackingStatus('error');
                addLog('error', data.message);
                toast.error('Password cracking failed');
                break;
                
            case 'stats_update':
                updateStats(data);
                break;
                
            case 'attack_stopped':
                handleAttackStopped(data);
                break;
                
            case 'error':
                setError(data.message);
                addLog('error', data.message);
                toast.error(data.message);
                break;
                
            default:
                console.log('Unknown message type:', type, data);
        }
    };

    const updateStats = (stats) => {
        setStats(stats);
        setPacketsSent(stats.packets_sent || 0);
        setEapolPackets(stats.eapol_packets || 0);
        setClientsDiscovered(stats.clients_discovered || 0);
        setProgress(stats.progress || 0);
        
        // Update status based on handshake and cracking
        if (stats.handshake_captured) {
            setHandshakeStatus('captured');
        }
        if (stats.cracking_status && stats.cracking_status !== 'not_started') {
            setCrackingStatus(stats.cracking_status);
        }
        if (stats.password_found) {
            setPasswordFound(stats.password_found);
        }
    };

    const handleAttackStopped = (data) => {
        setIsRunning(false);
        setIsLoading(false);
        setStatus('stopped');
        
        if (data.final_stats) {
            updateStats(data.final_stats);
        }
        
        addLog('info', data.message);
        toast.info('Handshake capture attack stopped');
        
        // Clear status polling
        if (statusIntervalRef.current) {
            clearInterval(statusIntervalRef.current);
            statusIntervalRef.current = null;
        }
    };

    const addLog = (level, message) => {
        const timestamp = new Date().toLocaleTimeString();
        const newLog = { timestamp, level, message };
        setLogs(prev => [...prev.slice(-49), newLog]); // Keep last 50 logs
    };

    const startAttack = async () => {
        if (!interface || !ssid || !bssid || !channel) {
            toast.error('Please fill in all required fields');
            return;
        }

        setIsLoading(true);
        setError(null);
        setLogs([]);
        setProgress(0);
        setStatus('starting');
        
        // Reset status tracking
        setHandshakeStatus('not_started');
        setCrackingStatus('not_started');
        setPasswordFound(null);
        setEapolMessages({});
        setClientsDiscovered(0);
        setPacketsSent(0);
        setEapolPackets(0);

        try {
            // Connect WebSocket if not already connected
            if (!wsRef.current) {
                connectWebSocket();
            }

            const response = await fetch('/api/attacks/handshake-capture/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    interface,
                    ssid,
                    bssid,
                    channel: parseInt(channel),
                    wordlist,
                    timeout,
                    deauth_count: deauthCount,
                    deauth_interval: deauthInterval,
                    output_dir: outputDir,
                    restore_managed: restoreManaged
                }),
            });

            const data = await response.json();

            if (data.status === 'success') {
                setIsRunning(true);
                setStatus('running');
                addLog('success', data.message);
                toast.success('Handshake capture attack started');
                
                // Start status polling
                startStatusPolling();
            } else {
                setError(data.message);
                addLog('error', data.message);
                toast.error(data.message);
            }
        } catch (error) {
            const errorMessage = error.message || 'Failed to start attack';
            setError(errorMessage);
            addLog('error', errorMessage);
            toast.error(errorMessage);
        } finally {
            setIsLoading(false);
        }
    };

    const stopAttack = async () => {
        setIsLoading(true);
        
        try {
            const response = await fetch('/api/attacks/handshake-capture/stop', {
                method: 'POST',
            });

            const data = await response.json();

            if (data.status === 'success') {
                setIsRunning(false);
                setStatus('stopped');
                addLog('info', data.message);
                toast.success('Attack stopped successfully');
                
                if (data.final_stats) {
                    updateStats(data.final_stats);
                }
            } else {
                toast.error(data.message);
            }
        } catch (error) {
            const errorMessage = error.message || 'Failed to stop attack';
            toast.error(errorMessage);
        } finally {
            setIsLoading(false);
        }
    };

    const startStatusPolling = () => {
        statusIntervalRef.current = setInterval(async () => {
            try {
                const response = await fetch('/api/attacks/handshake-capture/status');
                const data = await response.json();
                
                if (data.status === 'success' && data.current_stats) {
                    updateStats(data.current_stats);
                }
            } catch (error) {
                console.error('Status polling error:', error);
            }
        }, 2000);
    };

    const getStatusColor = () => {
        switch (status) {
            case 'running': return 'text-green-500';
            case 'stopped': return 'text-red-500';
            case 'starting': return 'text-yellow-500';
            default: return 'text-gray-500';
        }
    };

    const getHandshakeStatusIcon = () => {
        switch (handshakeStatus) {
            case 'captured': return <CheckCircle className="w-4 h-4 text-green-500" />;
            case 'not_started': return <Clock className="w-4 h-4 text-gray-500" />;
            default: return <AlertCircle className="w-4 h-4 text-yellow-500" />;
        }
    };

    const getCrackingStatusIcon = () => {
        switch (crackingStatus) {
            case 'success': return <Key className="w-4 h-4 text-green-500" />;
            case 'cracking': return <Clock className="w-4 h-4 text-blue-500" />;
            case 'failed': return <AlertCircle className="w-4 h-4 text-red-500" />;
            case 'timeout': return <AlertCircle className="w-4 h-4 text-orange-500" />;
            case 'error': return <AlertCircle className="w-4 h-4 text-red-500" />;
            default: return <Clock className="w-4 h-4 text-gray-500" />;
        }
    };

    return (
        <div className="space-y-6">
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="w-5 h-5" />
                        Handshake Capture Attack
                    </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                    {/* Configuration Section */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                            <Label htmlFor="interface">Interface *</Label>
                            <Select value={interface} onValueChange={setInterface}>
                                <SelectTrigger>
                                    <SelectValue placeholder="Select interface" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="wlan0">wlan0</SelectItem>
                                    <SelectItem value="wlan1">wlan1</SelectItem>
                                    <SelectItem value="wlan2">wlan2</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        
                        <div className="space-y-2">
                            <Label htmlFor="ssid">SSID *</Label>
                            <Input
                                id="ssid"
                                value={ssid}
                                onChange={(e) => setSsid(e.target.value)}
                                placeholder="Target network name"
                            />
                        </div>
                        
                        <div className="space-y-2">
                            <Label htmlFor="bssid">BSSID *</Label>
                            <Input
                                id="bssid"
                                value={bssid}
                                onChange={(e) => setBssid(e.target.value)}
                                placeholder="00:11:22:33:44:55"
                            />
                        </div>
                        
                        <div className="space-y-2">
                            <Label htmlFor="channel">Channel *</Label>
                            <Input
                                id="channel"
                                type="number"
                                value={channel}
                                onChange={(e) => setChannel(e.target.value)}
                                placeholder="1-165"
                                min="1"
                                max="165"
                            />
                        </div>
                    </div>

                    {/* Advanced Configuration */}
                    <div className="space-y-4">
                        <div className="flex items-center gap-2">
                            <Settings className="w-4 h-4" />
                            <h3 className="text-sm font-medium">Advanced Configuration</h3>
                        </div>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <div className="space-y-2">
                                <Label htmlFor="wordlist">Wordlist</Label>
                                <Input
                                    id="wordlist"
                                    value={wordlist}
                                    onChange={(e) => setWordlist(e.target.value)}
                                    placeholder="/path/to/wordlist"
                                />
                            </div>
                            
                            <div className="space-y-2">
                                <Label htmlFor="timeout">Timeout (seconds)</Label>
                                <Input
                                    id="timeout"
                                    type="number"
                                    value={timeout}
                                    onChange={(e) => setTimeout(parseInt(e.target.value))}
                                    min="10"
                                    max="300"
                                />
                            </div>
                            
                            <div className="space-y-2">
                                <Label htmlFor="deauthCount">Deauth Count</Label>
                                <Input
                                    id="deauthCount"
                                    type="number"
                                    value={deauthCount}
                                    onChange={(e) => setDeauthCount(parseInt(e.target.value))}
                                    min="1"
                                    max="50"
                                />
                            </div>
                            
                            <div className="space-y-2">
                                <Label htmlFor="deauthInterval">Deauth Interval (s)</Label>
                                <Input
                                    id="deauthInterval"
                                    type="number"
                                    step="0.1"
                                    value={deauthInterval}
                                    onChange={(e) => setDeauthInterval(parseFloat(e.target.value))}
                                    min="0.5"
                                    max="10.0"
                                />
                            </div>
                            
                            <div className="space-y-2">
                                <Label htmlFor="outputDir">Output Directory</Label>
                                <Input
                                    id="outputDir"
                                    value={outputDir}
                                    onChange={(e) => setOutputDir(e.target.value)}
                                    placeholder="/tmp/airstrike_captures"
                                />
                            </div>
                            
                            <div className="space-y-2">
                                <Label htmlFor="restoreManaged" className="flex items-center gap-2">
                                    <Monitor className="w-4 h-4" />
                                    Restore Managed Mode
                                </Label>
                                <div className="flex items-center space-x-2">
                                    <Switch
                                        id="restoreManaged"
                                        checked={restoreManaged}
                                        onCheckedChange={setRestoreManaged}
                                    />
                                    <span className="text-sm text-muted-foreground">
                                        {restoreManaged ? 'Yes' : 'No'}
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Attack Controls */}
                    <div className="flex gap-2">
                        <Button
                            onClick={startAttack}
                            disabled={isLoading || isRunning}
                            className="flex-1"
                        >
                            {isLoading ? (
                                <div className="flex items-center gap-2">
                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                                    Starting...
                                </div>
                            ) : (
                                <div className="flex items-center gap-2">
                                    <Play className="w-4 h-4" />
                                    Start Attack
                                </div>
                            )}
                        </Button>
                        
                        <Button
                            onClick={stopAttack}
                            disabled={!isRunning || isLoading}
                            variant="destructive"
                        >
                            <Square className="w-4 h-4" />
                            Stop
                        </Button>
                    </div>

                    {/* Status and Progress */}
                    {isRunning && (
                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <div className={`w-2 h-2 rounded-full ${getStatusColor().replace('text-', 'bg-')}`}></div>
                                    <span className="text-sm font-medium">Status: {status}</span>
                                </div>
                                <Badge variant="outline">{progress}%</Badge>
                            </div>
                            
                            <Progress value={progress} className="w-full" />
                            
                            {/* Real-time Statistics */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                <div className="text-center">
                                    <div className="text-2xl font-bold">{packetsSent}</div>
                                    <div className="text-xs text-muted-foreground">Packets Sent</div>
                                </div>
                                <div className="text-center">
                                    <div className="text-2xl font-bold">{eapolPackets}</div>
                                    <div className="text-xs text-muted-foreground">EAPOL Packets</div>
                                </div>
                                <div className="text-center">
                                    <div className="text-2xl font-bold">{clientsDiscovered}</div>
                                    <div className="text-xs text-muted-foreground">Clients Found</div>
                                </div>
                                <div className="text-center">
                                    <div className="text-2xl font-bold">{stats.duration || 0}s</div>
                                    <div className="text-xs text-muted-foreground">Duration</div>
                                </div>
                            </div>
                            
                            {/* Handshake and Cracking Status */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="flex items-center gap-2 p-3 border rounded-lg">
                                    {getHandshakeStatusIcon()}
                                    <div>
                                        <div className="font-medium">Handshake Status</div>
                                        <div className="text-sm text-muted-foreground">
                                            {handshakeStatus === 'captured' ? 'Captured' : 'Not captured'}
                                        </div>
                                    </div>
                                </div>
                                
                                <div className="flex items-center gap-2 p-3 border rounded-lg">
                                    {getCrackingStatusIcon()}
                                    <div>
                                        <div className="font-medium">Cracking Status</div>
                                        <div className="text-sm text-muted-foreground">
                                            {crackingStatus === 'success' ? 'Password found' :
                                             crackingStatus === 'cracking' ? 'In progress' :
                                             crackingStatus === 'failed' ? 'Failed' :
                                             crackingStatus === 'timeout' ? 'Timed out' :
                                             crackingStatus === 'error' ? 'Error' : 'Not started'}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            {/* Password Result */}
                            {passwordFound && (
                                <Alert>
                                    <Key className="h-4 w-4" />
                                    <AlertDescription>
                                        <strong>Password found:</strong> {passwordFound}
                                    </AlertDescription>
                                </Alert>
                            )}
                            
                            {/* EAPOL Messages Status */}
                            {Object.keys(eapolMessages).length > 0 && (
                                <div className="space-y-2">
                                    <div className="text-sm font-medium">EAPOL Messages:</div>
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                        {Object.entries(eapolMessages).map(([message, present]) => (
                                            <Badge key={message} variant={present ? "default" : "secondary"}>
                                                {message.replace('_', ' ')}: {present ? '✓' : '✗'}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Error Display */}
                    {error && (
                        <Alert variant="destructive">
                            <AlertCircle className="h-4 w-4" />
                            <AlertDescription>{error}</AlertDescription>
                        </Alert>
                    )}

                    {/* Logs */}
                    {logs.length > 0 && (
                        <div className="space-y-2">
                            <div className="flex items-center gap-2">
                                <FileText className="w-4 h-4" />
                                <h3 className="text-sm font-medium">Attack Logs</h3>
                            </div>
                            <div className="max-h-40 overflow-y-auto border rounded-lg p-2 space-y-1">
                                {logs.map((log, index) => (
                                    <div key={index} className="text-xs font-mono">
                                        <span className="text-muted-foreground">[{log.timestamp}]</span>
                                        <span className={`ml-2 ${
                                            log.level === 'error' ? 'text-red-500' :
                                            log.level === 'success' ? 'text-green-500' :
                                            log.level === 'warning' ? 'text-yellow-500' :
                                            'text-blue-500'
                                        }`}>
                                            {log.message}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    );
};

export default HandshakeCapture; 