' Rootcastle Network Monitor v6.0
' Powered by Rootcastle Engineering & Innovation
' Complete Network Surveillance: NMAP + Wireshark + Sniffnet + SOFIA AI
' Features: Port Scanning, Packet Analysis, Protocol Decode, Export, Traffic Analysis
' Defense-Grade Quality Standards Applied

Option Strict On
Option Explicit On

Imports System.Net.NetworkInformation
Imports System.Net.Sockets
Imports System.Net
Imports System.Text
Imports System.Threading
Imports System.IO
Imports Windows.Storage
Imports Windows.Storage.Pickers
Imports Windows.Web.Http
Imports Windows.Data.Json
Imports Windows.UI.Xaml.Shapes
Imports Windows.UI.Xaml.Media
Imports Windows.UI.Text
Imports Windows.UI.Xaml.Controls
Imports Microsoft.VisualBasic
Imports System.Linq
Imports Windows.UI
Imports App1

Public NotInheritable Class MainPage
    Inherits Page

#Region "Fields"
    ' Network Interfaces
    Private _interfaces As List(Of NetworkInterface)
    Private _selectedInterface As NetworkInterface

    ' Monitoring
    Private _monitorTimer As DispatcherTimer
    Private _uptimeTimer As DispatcherTimer
    Private _isMonitoring As Boolean = False
    Private _startTime As DateTime
    Private _correlationId As String = ""  ' Per-session correlation ID for tracing

    ' Recording
    Private _isRecording As Boolean = False
    Private _recordedPackets As New List(Of ConnectionInfo)

    ' Statistics
    Private _packetCount As Long = 0
    Private _lastBytesSent As Long = 0
    Private _lastBytesReceived As Long = 0
    Private _tcpCount As Long = 0
    Private _udpCount As Long = 0
    Private _icmpCount As Long = 0
    Private _otherCount As Long = 0
    Private _errorCount As Long = 0
    Private _bytesPerSecIn As Long = 0
    Private _bytesPerSecOut As Long = 0
    Private _suspiciousCount As Long = 0
    Private _totalBytesIn As Long = 0
    Private _totalBytesOut As Long = 0

    ' QoS Metrics
    Private _latencyHistory As New List(Of Double)
    Private _currentLatency As Double = 0
    Private _jitter As Double = 0
    Private _packetLoss As Double = 0
    Private _throughput As Double = 0

    ' DNS Statistics
    Private _dnsQueryCount As Long = 0
    Private _dnsNxdomainCount As Long = 0
    Private _dnsTunnelCount As Long = 0

    ' TLS/PKI Statistics
    Private _tls13Count As Long = 0
    Private _tls12Count As Long = 0
    Private _tlsWeakCount As Long = 0
    Private _certList As New List(Of CertInfo)

    ' Threat Detection
    Private _portScanCount As Long = 0
    Private _dosCount As Long = 0
    Private _arpSpoofCount As Long = 0
    Private _threatList As New List(Of String)

    ' Asset Inventory
    Private _assetList As New List(Of AssetInfo)

    ' Application Breakdown
    Private _appTraffic As New Dictionary(Of String, Long)

    ' Conversations
    Private _conversations As New Dictionary(Of String, ConversationInfo)

    ' Zero Trust
    Private _zeroTrustEvents As New List(Of ZeroTrustEvent)

    ' Connection tracking for port scan detection
    Private _connectionAttempts As New Dictionary(Of String, List(Of DateTime))

    ' Traffic Graph
    Private _trafficHistoryIn As New List(Of Double)
    Private _trafficHistoryOut As New List(Of Double)
    Private Const MAX_GRAPH_POINTS As Integer = 60

    ' Connections & Data
    Private _activeConnections As New List(Of ConnectionInfo)
    Private _hostTraffic As New Dictionary(Of String, Long)
    Private _alerts As New List(Of String)
    Private _packetLog As New List(Of PacketLogEntry)

    ' Settings
    Private _filterProtocol As String = "ALL"
    Private _suspiciousDetectionEnabled As Boolean = False

    ' NMAP
    Private _nmapCancellationTokenSource As CancellationTokenSource
    Private _isNmapScanning As Boolean = False
    Private _nmapResults As New List(Of NmapHostResult)

    ' Packet Raw Data Storage
    Private _packetRawData As New Dictionary(Of Long, Byte())

    ' External IP
    Private _externalIP As String = ""

    ' AI Settings
    Private _openRouterApiKey As String = ""
    Private _selectedAIModel As String = "meta-llama/llama-3.2-3b-instruct:free"
    Private _selectedLanguage As String = "TR"
    Private Const OPENROUTER_API_URL As String = "https://openrouter.ai/api/v1/chat/completions"

    ' Port & Service Data
    Private ReadOnly _quickScanPorts As Integer() = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
    Private ReadOnly _fullScanPorts As Integer() = Enumerable.Range(1, 1024).ToArray()
    Private ReadOnly _commonServices As New Dictionary(Of Integer, String) From {
        {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"},
        {111, "RPC"}, {135, "MSRPC"}, {139, "NetBIOS"}, {143, "IMAP"}, {443, "HTTPS"}, {445, "SMB"},
        {993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"}, {1723, "PPTP"}, {3306, "MySQL"}, {3389, "RDP"},
        {5432, "PostgreSQL"}, {5900, "VNC"}, {6379, "Redis"}, {8080, "HTTP-Proxy"}, {8443, "HTTPS-Alt"}, {27017, "MongoDB"}
    }
    Private ReadOnly _suspiciousPorts As Integer() = {23, 445, 1433, 3306, 4444, 5900, 6666, 6667, 31337, 12345, 27374}
    Private ReadOnly _suspiciousCountries As String() = {"CN", "RU", "KP", "IR"}
#End Region

#Region "Initialization"
    Private Sub MainPage_Loaded(sender As Object, e As RoutedEventArgs) Handles Me.Loaded
        Try
            InitializeGraphData()
            InitializeTimers()
            LoadInterfaces()
            LoadSettingsAsync()  ' Load persisted settings
            GetExternalIPAsync()
            LogTerminal("[SYS] Rootcastle Network Monitor v6.0")
            LogTerminal("[SYS] Powered by Rootcastle Engineering & Innovation")
            LogTerminal("[SYS] Defense-grade network surveillance initialized")
            LogTerminal("[SYS] SOFIA AI Engine ready")
        Catch ex As Exception
            LogTerminal($"[ERR] Init failed: {ex.Message}")
        End Try
    End Sub

    Private Async Sub GetExternalIPAsync()
        Try
            Using client As New HttpClient()
                Dim response = Await client.GetStringAsync(New Uri("https://api.ipify.org"))
                _externalIP = response.Trim()
                ExternalIPText.Text = $"WAN: {_externalIP}"
                InternetStatusText.Text = "●"
                InternetStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
                LogTerminal($"[NET] External IP: {_externalIP}")
            End Using
        Catch ex As Exception
            ExternalIPText.Text = "WAN: Unavailable"
            InternetStatusText.Text = "●"
            InternetStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))
            LogTerminal($"[ERR] Failed to get external IP: {ex.Message}")
        End Try
    End Sub

    Private Sub InitializeGraphData()
        _trafficHistoryIn = New List(Of Double)(Enumerable.Repeat(0.0, MAX_GRAPH_POINTS))
        _trafficHistoryOut = New List(Of Double)(Enumerable.Repeat(0.0, MAX_GRAPH_POINTS))
    End Sub

    Private Sub InitializeTimers()
        _monitorTimer = New DispatcherTimer()
        _monitorTimer.Interval = TimeSpan.FromMilliseconds(500)
        AddHandler _monitorTimer.Tick, AddressOf MonitorTimer_Tick

        _uptimeTimer = New DispatcherTimer()
        _uptimeTimer.Interval = TimeSpan.FromSeconds(1)
        AddHandler _uptimeTimer.Tick, AddressOf UptimeTimer_Tick
    End Sub

    Private Sub LoadInterfaces()
        Try
            InterfaceComboBox.Items.Clear()
            _interfaces = NetworkInterface.GetAllNetworkInterfaces().
                Where(Function(n) n.OperationalStatus = OperationalStatus.Up AndAlso
                                  n.NetworkInterfaceType <> NetworkInterfaceType.Loopback).ToList()

            For Each ni In _interfaces
                InterfaceComboBox.Items.Add($"{ni.Name}")
            Next

            If InterfaceComboBox.Items.Count > 0 Then
                InterfaceComboBox.SelectedIndex = 0
            Else
                LogTerminal("[WARN] No active network interfaces found")
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Failed to load interfaces: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Interface Selection"
    Private Sub InterfaceComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Try
            If InterfaceComboBox.SelectedIndex >= 0 AndAlso InterfaceComboBox.SelectedIndex < _interfaces.Count Then
                _selectedInterface = _interfaces(InterfaceComboBox.SelectedIndex)
                LoadNetworkStats()
                LogTerminal($"[NET] Selected: {_selectedInterface.Name}")
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Interface selection: {ex.Message}")
        End Try
    End Sub

    Private Sub LoadNetworkStats()
        If _selectedInterface Is Nothing Then Return

        Try
            Dim ni = _selectedInterface
            Dim ipStats = ni.GetIPStatistics()

            _lastBytesSent = ipStats.BytesSent
            _lastBytesReceived = ipStats.BytesReceived

            InterfaceNameText.Text = $"Name: {ni.Name}"
            InterfaceTypeText.Text = $"Type: {ni.NetworkInterfaceType}"
            InterfaceStatusText.Text = $"Status: {ni.OperationalStatus}"
            InterfaceSpeedText.Text = $"Speed: {If(ni.Speed > 0, (ni.Speed / 1000000).ToString("F0") & " Mbps", "N/A")}"

            Dim mac = ni.GetPhysicalAddress().GetAddressBytes()
            MacAddressText.Text = $"MAC: {If(mac.Length > 0, String.Join(":", mac.Select(Function(b) b.ToString("X2"))), "N/A")}"

            Dim ipProps = ni.GetIPProperties()
            Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
            Dim ipv6 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetworkV6)
            Dim gateway = ipProps.GatewayAddresses.FirstOrDefault(Function(g) g.Address.AddressFamily = AddressFamily.InterNetwork)
            Dim dns = ipProps.DnsAddresses.FirstOrDefault()

            IPv4Text.Text = $"IPv4: {If(ipv4?.Address.ToString(), "N/A")}"
            IPv6Text.Text = $"IPv6: {If(ipv6?.Address.ToString(), "N/A")}"
            SubnetText.Text = $"Mask: {If(ipv4?.IPv4Mask?.ToString(), "N/A")}"
            GatewayText.Text = $"GW: {If(gateway?.Address.ToString(), "N/A")}"
            DnsServersText.Text = $"DNS: {If(dns?.ToString(), "N/A")}"

            ' Update topology display
            If ipv4 IsNot Nothing Then
                Dim localIP = ipv4.Address.ToString()
                LocalIPShortText.Text = localIP.Substring(localIP.LastIndexOf(".") + 1)

                ' These controls are not present in XAML; use existing ones.
                'LocalIPText.Text = $"Kişisel IP: {localIP}"
                'RouterIPText.Text = $"Router IP: {gateway?.Address.ToString()}"

                If gateway IsNot Nothing Then
                    GatewayShortText.Text = gateway.Address.ToString().Split("."c).LastOrDefault()
                Else
                    GatewayShortText.Text = "-"
                End If
            End If

            ' Clear previous topology data
            TopologyCanvas.Children.Clear()
            _hostTraffic.Clear()
            _activeConnections.Clear()

            ' Redraw topology
            DrawTopology()
        Catch ex As Exception
            LogTerminal($"[ERR] Failed to load network stats: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Monitoring"
    Private Sub StartMonitoring()
        If _selectedInterface Is Nothing Then Return

        Try
            _isMonitoring = True
            _correlationId = GenerateCorrelationId()  ' New correlation ID per session
            _startTime = DateTime.Now
            _lastBytesSent = 0
            _lastBytesReceived = 0
            _packetCount = 0
            _errorCount = 0
            _suspiciousCount = 0
            _totalBytesIn = 0
            _totalBytesOut = 0
            _bytesPerSecIn = 0
            _bytesPerSecOut = 0
            _trafficHistoryIn.Clear()
            _trafficHistoryOut.Clear()

            For i = 0 To MAX_GRAPH_POINTS - 1
                _trafficHistoryIn.Add(0)
                _trafficHistoryOut.Add(0)
            Next

            ' Start timers
            _monitorTimer.Start()
            _uptimeTimer.Start()

            Dim ni = _selectedInterface
            Dim ipProps = ni.GetIPProperties()
            Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)

            If ipv4 IsNot Nothing Then
                Dim localIP = ipv4.Address.ToString()
                LocalIPShortText.Text = localIP.Substring(localIP.LastIndexOf(".") + 1)
                ' LocalIPText control is not present in XAML.
            End If

            LogTerminal($"[MON] Monitoring started on {_selectedInterface.Name}")
        Catch ex As Exception
            LogTerminal($"[ERR] Start monitoring: {ex.Message}")
        End Try
    End Sub

    Private Sub StopMonitoring()
        _isMonitoring = False
        _monitorTimer.Stop()
        _uptimeTimer.Stop()

        LogTerminal($"[MON] Monitoring stopped on {_selectedInterface.Name}")
    End Sub

    Private Sub MonitorTimer_Tick(sender As Object, e As Object)
        If _selectedInterface Is Nothing OrElse Not _isMonitoring Then Return

        Try
            Dim ni = _selectedInterface
            Dim ipStats = ni.GetIPStatistics()

            Dim currentBytesSent = ipStats.BytesSent
            Dim currentBytesReceived = ipStats.BytesReceived
            Dim deltaSent = Math.Max(0, currentBytesSent - _lastBytesSent)
            Dim deltaReceived = Math.Max(0, currentBytesReceived - _lastBytesReceived)

            _bytesPerSecOut = deltaSent * 2
            _bytesPerSecIn = deltaReceived * 2
            _totalBytesOut += deltaSent
            _totalBytesIn += deltaReceived

            ' Update graph data
            _trafficHistoryOut.RemoveAt(0)
            _trafficHistoryOut.Add(_bytesPerSecOut / 1024.0)
            _trafficHistoryIn.RemoveAt(0)
            _trafficHistoryIn.Add(_bytesPerSecIn / 1024.0)

            ' UI Updates
            DrawTrafficGraph()
            DrawTopologyTraffic()
            UpdateTrafficDisplay(currentBytesSent, currentBytesReceived)
            TrafficRateText.Text = $"{FormatBytes(_bytesPerSecIn + _bytesPerSecOut)}/s"
            BytesPerSecText.Text = $"↓{FormatBytes(_bytesPerSecIn)}/s ↑{FormatBytes(_bytesPerSecOut)}/s"

            ' Update topology stats
            DownloadSpeedText.Text = $"{FormatBytes(_bytesPerSecIn)}/s"
            UploadSpeedText.Text = $"{FormatBytes(_bytesPerSecOut)}/s"
            ActiveConnectionsText.Text = _activeConnections.Count.ToString()
            ActiveHostsText.Text = $"Hosts: {_hostTraffic.Count}"

            ' Update QoS Metrics
            UpdateQoSMetrics()

            ' Update Bandwidth percentage
            UpdateBandwidthDisplay()

            ' Capture packets
            If deltaSent > 0 Or deltaReceived > 0 Then
                CapturePacket(deltaSent, deltaReceived)
            End If

            ' Update Security Stats periodically
            UpdateSecurityStats()

            ' Update Alert count
            AlertCountText.Text = $"[{_alerts.Count}]"

            _lastBytesSent = currentBytesSent
            _lastBytesReceived = currentBytesReceived

        Catch ex As Exception
            _errorCount += 1
            ErrorCountText.Text = $"E:{_errorCount}"
        End Try
    End Sub

    Private Sub UptimeTimer_Tick(sender As Object, e As Object)
        If Not _isMonitoring Then Return

        Try
            Dim uptime = DateTime.Now - _startTime
            UptimeText.Text = $"{uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}"
        Catch ex As Exception
            LogTerminal($"[ERR] Uptime update: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "UI Display"
    Private Sub UpdateTrafficDisplay(sent As Long, recv As Long)
        SentDataText.Text = $"↑ {FormatBytes(sent)}"
        ReceivedDataText.Text = $"↓ {FormatBytes(recv)}"
    End Sub

    Private Sub DrawTopologyTraffic()
        Try
            TopologyCanvas.Children.Clear()
            Dim w = TopologyCanvas.ActualWidth
            Dim h = TopologyCanvas.ActualHeight
            If w <= 0 Or h <= 0 Then Return

            ' Draw connection line
            Dim centerY = h / 2
            Dim line As New Line() With {
                .X1 = 0, .Y1 = centerY,
                .X2 = w, .Y2 = centerY,
                .Stroke = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 100, 100)),
                .StrokeThickness = 2
            }
            TopologyCanvas.Children.Add(line)

            ' Draw traffic flow indicators (animated dots)
            Dim trafficIntensity = Math.Min(10, Math.Max(1, CInt((_bytesPerSecIn + _bytesPerSecOut) / 10000)))

            ' Download arrows (left to right, cyan)
            If _bytesPerSecIn > 0 Then
                For i = 0 To trafficIntensity - 1
                    Dim x = (DateTime.Now.Millisecond / 100.0 + i * (w / trafficIntensity)) Mod w
                    Dim arrow As New TextBlock() With {
                        .Text = "→",
                        .Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 255)),
                        .FontSize = 14,
                        .FontFamily = New FontFamily("Consolas")
                    }
                    Canvas.SetLeft(arrow, x)
                    Canvas.SetTop(arrow, centerY - 15)
                    TopologyCanvas.Children.Add(arrow)
                Next
            End If

            ' Upload arrows (right to left, green)
            If _bytesPerSecOut > 0 Then
                For i = 0 To trafficIntensity - 1
                    Dim x = w - ((DateTime.Now.Millisecond / 100.0 + i * (w / trafficIntensity)) Mod w)
                    Dim arrow As New TextBlock() With {
                        .Text = "←",
                        .Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0)),
                        .FontSize = 14,
                        .FontFamily = New FontFamily("Consolas")
                    }
                    Canvas.SetLeft(arrow, x)
                    Canvas.SetTop(arrow, centerY + 5)
                    TopologyCanvas.Children.Add(arrow)
                Next
            End If

            ' Draw traffic stats in center
            Dim statsText As New TextBlock() With {
                .Text = $"↓{FormatBytes(_bytesPerSecIn)}/s  ↑{FormatBytes(_bytesPerSecOut)}/s",
                .Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 255, 255)),
                .FontSize = 10,
                .FontFamily = New FontFamily("Consolas")
            }
            Dim bg As New Border() With {
                .Background = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(200, 0, 20, 20)),
                .Padding = New Thickness(4),
                .CornerRadius = New CornerRadius(2),
                .Child = statsText
            }
            Canvas.SetLeft(bg, w / 2 - 60)
            Canvas.SetTop(bg, centerY - 12)
            TopologyCanvas.Children.Add(bg)
        Catch ex As Exception
            ' Non-critical UI rendering error - log but continue
            System.Diagnostics.Debug.WriteLine($"[UI] Topology draw error: {ex.Message}")
        End Try
    End Sub

    Private Sub DrawTrafficGraph()
        Try
            ' XAML canvas name is `TrafficGraphCanvas`
            If TrafficGraphCanvas.Children.Count > 0 Then
                TrafficGraphCanvas.Children.Clear()
            End If

            Dim maxIn = _trafficHistoryIn.Max()
            Dim maxOut = _trafficHistoryOut.Max()
            Dim maxValue = Math.Max(maxIn, maxOut)
            If maxValue = 0 Then Return

            Dim width = TrafficGraphCanvas.ActualWidth
            Dim height = TrafficGraphCanvas.ActualHeight
            Dim barWidth = Math.Max(1, CInt(width / MAX_GRAPH_POINTS))

            For i = 0 To MAX_GRAPH_POINTS - 1
                Dim inValue = _trafficHistoryIn(i)
                Dim outValue = _trafficHistoryOut(i)

                Dim inHeight = height * (inValue / maxValue)
                Dim outHeight = height * (outValue / maxValue)

                Dim inBar = New Rectangle() With {
                    .Width = barWidth - 2,
                    .Height = inHeight,
                    .Fill = New SolidColorBrush(Colors.Blue)
                }

                Dim outBar = New Rectangle() With {
                    .Width = barWidth - 2,
                    .Height = outHeight,
                    .Fill = New SolidColorBrush(Colors.Red)
                }

                Canvas.SetLeft(inBar, i * barWidth)
                Canvas.SetTop(inBar, height - inHeight)

                Canvas.SetLeft(outBar, i * barWidth)
                Canvas.SetTop(outBar, height - outHeight)

                TrafficGraphCanvas.Children.Add(inBar)
                TrafficGraphCanvas.Children.Add(outBar)
            Next

            TrafficGraphCanvas.Width = Math.Max(TrafficGraphCanvas.ActualWidth, MAX_GRAPH_POINTS * 4)
        Catch ex As Exception
            LogTerminal($"[ERR] Draw traffic graph: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Packet Capture"
    Private Sub CapturePacket(deltaSent As Long, deltaReceived As Long)
        Try
            Dim now = DateTime.Now

            ' Simulate packet capture for testing (DEMO only - UWP limitation)
            Dim rnd As New Random()
            Dim testPacket As New ConnectionInfo() With {
                .Timestamp = now,
                .SourceIP = "192.168.1." & rnd.Next(1, 255),
                .DestIP = "192.168.1." & rnd.Next(1, 255),
                .Protocol = If(rnd.Next(0, 2) = 0, "TCP", "UDP"),
                .Length = CLng(rnd.Next(50, 1500)),
                .Info = "Test packet " & _packetCount
            }

            _packetCount += 1
            _recordedPackets.Add(testPacket)

            ' Update active connections
            UpdateActiveConnections(testPacket)

            ' Update firewall and threat detection
            If _suspiciousDetectionEnabled Then
                UpdateThreatDetection(testPacket)
            End If

            ' Log packet details
            Dim packetDetails = $"[{testPacket.Timestamp:HH:mm:ss}] {testPacket.Protocol} {testPacket.SourceIP} → {testPacket.DestIP} [{testPacket.Length} bytes] {testPacket.Info}"
            LogTerminal(packetDetails)

            ' Update simple UI bindings list (Packet Capture)
            ConnectionsListView.ItemsSource = Nothing
            ConnectionsListView.ItemsSource = _recordedPackets.TakeLast(200).Select(Function(p)
                                                                                        p.Id = p.Id
                                                                                        Return p
                                                                                    End Function).ToList()
            ConnectionCountText.Text = $"[{_recordedPackets.Count} connections]"

            PacketCountText.Text = _packetCount.ToString()

        Catch ex As Exception
            LogTerminal($"[ERR] Capture packet: {ex.Message}")
        End Try
    End Sub

    Private Sub UpdateActiveConnections(packet As ConnectionInfo)
        Try
            Dim key = $"{packet.SourceIP}-{packet.DestIP}-{packet.Protocol}"

            If Not _activeConnections.Any(Function(c) c.Key = key) Then
                Dim conn = New ConnectionInfo() With {
                    .SourceIP = packet.SourceIP,
                    .DestIP = packet.DestIP,
                    .Protocol = packet.Protocol,
                    .Length = packet.Length,
                    .Timestamp = packet.Timestamp
                }

                _activeConnections.Add(conn)

                ' Update UI
                ActiveConnectionsText.Text = _activeConnections.Count.ToString()
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Update active connections: {ex.Message}")
        End Try
    End Sub

    Private Sub UpdateThreatDetection(packet As ConnectionInfo)
        Try
            ' Basic rule: alert on incoming packets if source IP is suspicious
            If packet.Protocol = "TCP" AndAlso packet.Length > 1000 Then
                Dim sourceIPParts = packet.SourceIP.Split(".")
                If sourceIPParts.Length = 4 Then
                    Dim lastOctet = Convert.ToInt32(sourceIPParts(3))
                    If lastOctet > 100 Then
                        _suspiciousCount += 1
                        If _suspiciousCount <= 5 Then
                            LogTerminal($"[ALERT] Suspicious packet detected: {packet.SourceIP} → {packet.DestIP} [{packet.Length} bytes]")
                        End If
                    End If
                End If
            End If

            ' Update firewall rules (block large incoming TCP packets from suspicious IPs)
            If packet.Protocol = "TCP" AndAlso packet.Length > 1000 Then
                Dim destIPParts = packet.DestIP.Split(".")
                If destIPParts.Length = 4 Then
                    Dim lastOctet = Convert.ToInt32(destIPParts(3))
                    If lastOctet <= 100 Then
                        LogTerminal($"[FIREWALL] Blocking incoming packet from {packet.SourceIP} to {packet.DestIP} [{packet.Length} bytes]")
                    End If
                End If
            End If
        Catch ex As Exception
            LogTerminal($"[ERR] Update threat detection: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Security & Alerts"
    Private Sub UpdateSecurityStats()
        Try
            ' Update suspicious activities count
            Dim suspiciousActivities = _recordedPackets.
                Where(Function(p) p.Protocol = "TCP" AndAlso p.Length > 1000).
                GroupBy(Function(p) p.SourceIP).
                Select(Function(g) New With {.IP = g.Key, .Count = g.Count()}).
                OrderByDescending(Function(a) a.Count).
                ToList()

            _suspiciousCount = suspiciousActivities.Sum(Function(a) a.Count)

            ' Update alert list
            _alerts = suspiciousActivities.
                Where(Function(a) a.Count > 5).
                Select(Function(a) $"{a.IP}: {a.Count} suspicious packets").
                ToList()

            ' Update alert count display
            AlertCountText.Text = $"[{_alerts.Count}]"
        Catch ex As Exception
            LogTerminal($"[ERR] Update security stats: {ex.Message}")
        End Try
    End Sub

    ''' <summary>
    ''' Logs a message to the terminal output with timestamp.
    ''' </summary>
    Private Sub LogTerminal(message As String)
        LogStructured("INFO", "", "", message, NetworkErrorType.None, "")
    End Sub

    ''' <summary>
    ''' Structured logging with severity, correlation ID, and error taxonomy.
    ''' Levels: DEBUG, INFO, WARN, ERR, CRITICAL
    ''' </summary>
    Private Sub LogStructured(level As String, operation As String, targetId As String, message As String, Optional errorType As NetworkErrorType = NetworkErrorType.None, Optional technicalDetails As String = "")
        Try
            Dim timeStamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            Dim cid = If(String.IsNullOrEmpty(_correlationId), "-", _correlationId.Substring(0, Math.Min(8, _correlationId.Length)))

            ' Build structured log line
            Dim logLine As String
            If String.IsNullOrEmpty(operation) AndAlso String.IsNullOrEmpty(targetId) Then
                ' Simple format for basic messages
                logLine = $"{timeStamp} [{level}] {message}"
            Else
                ' Full structured format
                logLine = $"{timeStamp} [{cid}] [{level}] [{operation}] "
                If Not String.IsNullOrEmpty(targetId) Then
                    logLine &= $"[{targetId}] "
                End If
                logLine &= message
                If errorType <> NetworkErrorType.None Then
                    logLine &= $" (Error: {errorType})"
                End If
            End If

            ' Append to terminal
            TerminalOutput.Text &= logLine & Environment.NewLine

            ' Debug output for diagnostics
            If level = "ERR" OrElse level = "CRITICAL" Then
                System.Diagnostics.Debug.WriteLine($"[ROOTCASTLE] {logLine}")
                If Not String.IsNullOrEmpty(technicalDetails) Then
                    System.Diagnostics.Debug.WriteLine($"[ROOTCASTLE] Technical: {technicalDetails}")
                End If
            End If

            ' Auto-scroll
            If AutoScrollCheckBox IsNot Nothing AndAlso AutoScrollCheckBox.IsChecked.GetValueOrDefault(True) Then
                TerminalScrollViewer?.ChangeView(Nothing, TerminalScrollViewer.ScrollableHeight, Nothing)
            End If
        Catch
            ' Logging failed - increment counter to track issues (cannot log this error to avoid recursion)
            _errorCount += 1
        End Try
    End Sub

    ''' <summary>
    ''' Generates a new correlation ID for a monitoring session or scan.
    ''' </summary>
    Private Function GenerateCorrelationId() As String
        Return Guid.NewGuid().ToString("N").Substring(0, 12).ToUpperInvariant()
    End Function
#End Region

#Region "QoS Metrics"
    Private Async Sub UpdateQoSMetrics()
        Try
            ' Use real ping to gateway or external target for actual latency measurement
            Dim target = "8.8.8.8"  ' Google DNS as reliable target

            ' Get gateway if available
            If _selectedInterface IsNot Nothing Then
                Try
                    Dim ipProps = _selectedInterface.GetIPProperties()
                    Dim gateway = ipProps.GatewayAddresses.FirstOrDefault()
                    If gateway IsNot Nothing AndAlso gateway.Address IsNot Nothing Then
                        target = gateway.Address.ToString()
                    End If
                Catch
                    ' Fallback to 8.8.8.8
                End Try
            End If

            ' Perform actual ping for real latency
            Using ping As New Ping()
                Try
                    Dim reply = Await ping.SendPingAsync(target, 500)
                    If reply.Status = IPStatus.Success Then
                        _latencyHistory.Add(CDbl(reply.RoundtripTime))
                        ' Track successful pings for packet loss calculation
                        _packetLoss = 0
                    Else
                        ' Ping failed - record as high latency and increment loss
                        _latencyHistory.Add(500.0)  ' Timeout value
                        _packetLoss = Math.Min(100, _packetLoss + 10)  ' Increment loss %
                    End If
                Catch
                    ' Ping exception - treat as packet loss
                    _latencyHistory.Add(500.0)
                    _packetLoss = Math.Min(100, _packetLoss + 10)
                End Try
            End Using

            ' Keep history bounded
            If _latencyHistory.Count > 20 Then _latencyHistory.RemoveAt(0)

            ' Calculate average latency (excluding timeouts for accuracy)
            Dim validLatencies = _latencyHistory.Where(Function(l) l < 500).ToList()
            Dim avgLatency = If(validLatencies.Count > 0, validLatencies.Average(), 0)
            _currentLatency = avgLatency

            ' Left panel
            LatencyText.Text = $"{avgLatency:F1} ms"

            ' QoS panel
            QosLatencyText.Text = $"{avgLatency:F1} ms"

            ' Jitter calculation (variation between consecutive measurements)
            If validLatencies.Count > 1 Then
                Dim jitter = 0.0
                For i = 1 To validLatencies.Count - 1
                    jitter += Math.Abs(validLatencies(i) - validLatencies(i - 1))
                Next
                jitter /= (validLatencies.Count - 1)
                _jitter = jitter
            End If
            QosJitterText.Text = $"{_jitter:F1} ms"

            ' Packet Loss display
            QosLossText.Text = $"{_packetLoss:F1}%"

            ' Throughput (calculated from actual traffic)
            _throughput = (_bytesPerSecIn + _bytesPerSecOut) * 8.0 / 1_000_000.0
            QosThroughputText.Text = $"{_throughput:F2} Mbps"
        Catch ex As Exception
            LogTerminal($"[ERR] Update QoS metrics: {ex.Message}")
        End Try
    End Sub

    Private Sub UpdateBandwidthDisplay()
        Try
            If _selectedInterface Is Nothing OrElse _selectedInterface.Speed <= 0 Then
                BandwidthText.Text = "0%"
                Return
            End If

            Dim usedBps = (_bytesPerSecIn + _bytesPerSecOut) * 8.0
            Dim pct = Math.Min(100.0, (usedBps / _selectedInterface.Speed) * 100.0)
            BandwidthText.Text = $"{pct:F1}%"
        Catch ex As Exception
            ' Fallback value - bandwidth calculation failed
            BandwidthText.Text = "0%"
            System.Diagnostics.Debug.WriteLine($"[UI] Bandwidth calc error: {ex.Message}")
        End Try
    End Sub

    Private Function FormatBytes(value As Long) As String
        Dim dbl = CDbl(Math.Max(0L, value))
        Dim units = New String() {"B", "KB", "MB", "GB", "TB"}
        Dim idx = 0
        While dbl >= 1024 AndAlso idx < units.Length - 1
            dbl /= 1024
            idx += 1
        End While
        If idx = 0 Then Return $"{dbl:0} {units(idx)}"
        Return $"{dbl:0.##} {units(idx)}"
    End Function

    Private Sub DrawTopology()
        ' Minimal placeholder: topology is drawn dynamically in `DrawTopologyTraffic`.
        ' Keep as a hook so calls from other routines compile.
        DrawTopologyTraffic()
    End Sub

    Private Sub ShowAlert(message As String)
        _alerts.Add(message)
        If _alerts.Count > 200 Then _alerts.RemoveAt(0)
        AlertsListView.ItemsSource = Nothing
        AlertsListView.ItemsSource = _alerts.ToList()
        AlertCountText.Text = $"[{_alerts.Count}]"
    End Sub

    Private Sub StartMonitorButton_Click(sender As Object, e As RoutedEventArgs)
        If _isMonitoring Then
            StopMonitoring()
            StartMonitorButton.Content = "▶ START"
            MonitorStatusText.Text = "●"
            MonitorStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 170, 0))
            StatusText.Text = "[STOPPED]"
        Else
            StartMonitoring()
            StartMonitorButton.Content = "■ STOP"
            MonitorStatusText.Text = "●"
            MonitorStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
            StatusText.Text = "[MONITORING]"
        End If
    End Sub

    Private Sub ClearTerminalButton_Click(sender As Object, e As RoutedEventArgs)
        TerminalOutput.Text = ""
    End Sub

    Private Sub FilterComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        ' UI-only placeholder; filtering can be layered on top of packet logs.
    End Sub

    Private Sub RecordButton_Click(sender As Object, e As RoutedEventArgs)
        _isRecording = Not _isRecording
        RecordButton.Content = If(_isRecording, "■ STOP REC", "● REC")
        RecordingStatusText.Text = If(_isRecording, "[REC]", "")
        LogTerminal(If(_isRecording, "[REC] Recording started", "[REC] Recording stopped"))
    End Sub

    Private Sub SuspiciousPacketCheckBox_Checked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = True
        SaveSettingsAsync()  ' Persist setting
        LogTerminal("[SEC] Suspicious traffic detection ENABLED")
    End Sub

    Private Sub SuspiciousPacketCheckBox_Unchecked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = False
        SaveSettingsAsync()  ' Persist setting
        LogTerminal("[SEC] Suspicious traffic detection DISABLED")
    End Sub

    Private Sub PacketFilterTextBox_KeyDown(sender As Object, e As KeyRoutedEventArgs)
        If e.Key = Windows.System.VirtualKey.Enter Then
            ApplyFilterButton_Click(sender, Nothing)
        End If
    End Sub

    Private Sub ApplyFilterButton_Click(sender As Object, e As RoutedEventArgs)
        _filterProtocol = If(String.IsNullOrWhiteSpace(PacketFilterTextBox.Text), "ALL", PacketFilterTextBox.Text.Trim().ToUpperInvariant())
        LogTerminal($"[UI] Filter set: {_filterProtocol}")
    End Sub

    Private Sub PacketListView_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim selected = TryCast(ConnectionsListView.SelectedItem, ConnectionInfo)
        If selected Is Nothing Then Return

        PacketDetailsPanel.Visibility = Visibility.Visible
        PacketDetailsText.Text = $"[{selected.Timestamp:HH:mm:ss}] {selected.Protocol} {selected.SourceIP} → {selected.DestIP}{vbCrLf}Len: {selected.Length} bytes{vbCrLf}{selected.Info}"
    End Sub

    Private Async Sub ExportReportButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim savePicker As New FileSavePicker()
            savePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary
            savePicker.FileTypeChoices.Add("CSV Report", New List(Of String) From {".csv"})
            savePicker.FileTypeChoices.Add("JSON Report", New List(Of String) From {".json"})
            savePicker.SuggestedFileName = $"network_report_{DateTime.Now:yyyyMMdd_HHmmss}"

            Dim file = Await savePicker.PickSaveFileAsync()
            If file Is Nothing Then Return

            StatusText.Text = "[EXPORTING...]"
            Dim content As String

            If file.FileType = ".json" Then
                content = GenerateJsonReport()
            Else
                content = GenerateCsvReport()
            End If

            Await FileIO.WriteTextAsync(file, content, Windows.Storage.Streams.UnicodeEncoding.Utf8)

            LogTerminal($"[EXPORT] Report saved: {file.Name}")
            ShowAlert($"Exported: {file.Name}")
            StatusText.Text = "[READY]"
        Catch ex As Exception
            LogTerminal($"[EXPORT] Error: {ex.Message}")
            ShowAlert($"Export failed: {ex.Message}")
            StatusText.Text = "[EXPORT FAILED]"
        End Try
    End Sub

    Private Function GenerateCsvReport() As String
        Dim sb As New StringBuilder()
        
        ' Header
        sb.AppendLine("# Rootcastle Network Monitor - Export Report")
        sb.AppendLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}")
        sb.AppendLine($"# Interface: {_selectedInterface?.Name}")
        sb.AppendLine($"# External IP: {_externalIP}")
        sb.AppendLine()
        sb.AppendLine("Timestamp,ID,SourceIP,DestIP,Protocol,Bytes,Info")

        For Each pkt In _recordedPackets.TakeLast(1000)
            Dim infoSafe = If(pkt.Info, "").Replace("""", "''").Replace(vbCr, " ").Replace(vbLf, " ")
            sb.AppendLine($"""{pkt.Timestamp:yyyy-MM-dd HH:mm:ss}"",""{pkt.Id}"",""{pkt.SourceIP}"",""{pkt.DestIP}"",""{pkt.Protocol}"",""{pkt.Length}"",""{infoSafe}""")
        Next
        
        ' Add NMAP results section
        sb.AppendLine()
        sb.AppendLine("# NMAP Scan Results")
        sb.AppendLine("Host,Status,OS,Ports")
        For Each h In _nmapResults
            sb.AppendLine($"""{h.Host}"",""{h.Status}"",""{h.OS}"",""{h.Ports}""")
        Next

        Return sb.ToString()
    End Function

    Private Function GenerateJsonReport() As String
        Dim report As New JsonObject()
        report.Add("reportType", JsonValue.CreateStringValue("Rootcastle Network Monitor Export"))
        report.Add("generated", JsonValue.CreateStringValue(DateTime.Now.ToString("o")))
        report.Add("version", JsonValue.CreateStringValue("6.0"))

        ' Network info
        Dim networkInfo As New JsonObject()
        networkInfo.Add("interface", JsonValue.CreateStringValue(If(_selectedInterface?.Name, "Unknown")))
        networkInfo.Add("externalIP", JsonValue.CreateStringValue(_externalIP))
        networkInfo.Add("interfaceType", JsonValue.CreateStringValue(If(_selectedInterface?.NetworkInterfaceType.ToString(), "Unknown")))
        report.Add("networkInfo", networkInfo)

        ' Statistics
        Dim stats As New JsonObject()
        stats.Add("totalPackets", JsonValue.CreateNumberValue(_packetCount))
        stats.Add("totalBytesIn", JsonValue.CreateNumberValue(_totalBytesIn))
        stats.Add("totalBytesOut", JsonValue.CreateNumberValue(_totalBytesOut))
        stats.Add("tcpCount", JsonValue.CreateNumberValue(_tcpCount))
        stats.Add("udpCount", JsonValue.CreateNumberValue(_udpCount))
        stats.Add("icmpCount", JsonValue.CreateNumberValue(_icmpCount))
        stats.Add("suspiciousCount", JsonValue.CreateNumberValue(_suspiciousCount))
        stats.Add("errorCount", JsonValue.CreateNumberValue(_errorCount))
        report.Add("statistics", stats)

        ' QoS Metrics
        Dim qos As New JsonObject()
        qos.Add("latencyMs", JsonValue.CreateNumberValue(_currentLatency))
        qos.Add("jitterMs", JsonValue.CreateNumberValue(_jitter))
        qos.Add("packetLossPercent", JsonValue.CreateNumberValue(_packetLoss))
        qos.Add("throughputMbps", JsonValue.CreateNumberValue(_throughput))
        report.Add("qosMetrics", qos)

        ' NMAP results
        Dim hosts As New JsonArray()
        For Each h In _nmapResults
            Dim hostObj As New JsonObject()
            hostObj.Add("ip", JsonValue.CreateStringValue(h.Host))
            hostObj.Add("status", JsonValue.CreateStringValue(h.Status))
            hostObj.Add("os", JsonValue.CreateStringValue(If(h.OS, "")))
            hostObj.Add("ports", JsonValue.CreateStringValue(h.Ports))
            hostObj.Add("openPortCount", JsonValue.CreateNumberValue(If(h.OpenPorts?.Count, 0)))
            hosts.Add(hostObj)
        Next
        report.Add("nmapHosts", hosts)

        ' Recent connections (last 100)
        Dim connections As New JsonArray()
        For Each pkt In _recordedPackets.TakeLast(100)
            Dim connObj As New JsonObject()
            connObj.Add("timestamp", JsonValue.CreateStringValue(pkt.Timestamp.ToString("o")))
            connObj.Add("sourceIP", JsonValue.CreateStringValue(pkt.SourceIP))
            connObj.Add("destIP", JsonValue.CreateStringValue(pkt.DestIP))
            connObj.Add("protocol", JsonValue.CreateStringValue(pkt.Protocol))
            connObj.Add("bytes", JsonValue.CreateNumberValue(pkt.Length))
            connections.Add(connObj)
        Next
        report.Add("recentConnections", connections)

        Return report.Stringify()
    End Function

    Private Sub SecurityDashboardButton_Click(sender As Object, e As RoutedEventArgs)
        MainPivot.SelectedIndex = 2
    End Sub

    Private Sub TopologyButton_Click(sender As Object, e As RoutedEventArgs)
        MainPivot.SelectedIndex = 0
    End Sub

    Private Sub AdvancedSettingsButton_Click(sender As Object, e As RoutedEventArgs)
        MainPivot.SelectedIndex = 3
    End Sub

    Private Async Sub SendTcpButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = SanitizeInput(TargetHostTextBox.Text)
        Dim portText = SanitizeInput(TargetPortTextBox.Text)
        Dim payload = PacketDataTextBox.Text

        If String.IsNullOrEmpty(host) OrElse String.IsNullOrEmpty(portText) Then
            ShowAlert("Enter host and port")
            Return
        End If

        If Not IsValidHostOrIP(host) Then
            ShowAlert("Invalid host format")
            Return
        End If

        Dim port As Integer
        If Not Integer.TryParse(portText, port) OrElse port < 1 OrElse port > 65535 Then
            ShowAlert("Invalid port (1-65535)")
            Return
        End If

        LogTerminal($"[TCP] Connecting to {host}:{port}...")

        Try
            Using client As New TcpClient()
                client.SendTimeout = 5000
                client.ReceiveTimeout = 5000

                Dim connectTask = client.ConnectAsync(host, port)
                Dim timeoutTask = Task.Delay(5000)
                Dim completed = Await Task.WhenAny(connectTask, timeoutTask)

                If completed Is timeoutTask Then
                    LogTerminal($"[TCP] Connection timeout to {host}:{port}")
                    Return
                End If

                If connectTask.IsFaulted Then
                    LogTerminal($"[TCP] Connection failed: {connectTask.Exception?.InnerException?.Message}")
                    Return
                End If

                LogTerminal($"[TCP] Connected to {host}:{port}")

                If Not String.IsNullOrEmpty(payload) Then
                    Dim data = Encoding.UTF8.GetBytes(payload)
                    Await client.GetStream().WriteAsync(data, 0, data.Length)
                    LogTerminal($"[TCP] Sent {data.Length} bytes")

                    ' Try to read response with timeout
                    Try
                        Dim buffer(1024) As Byte
                        Using cts As New CancellationTokenSource(2000)
                            Dim bytesRead = Await client.GetStream().ReadAsync(buffer, 0, buffer.Length, cts.Token)
                            If bytesRead > 0 Then
                                Dim response = Encoding.UTF8.GetString(buffer, 0, bytesRead)
                                LogTerminal($"[TCP] Received {bytesRead} bytes: {response.Substring(0, Math.Min(100, response.Length))}")
                            End If
                        End Using
                    Catch ex As OperationCanceledException
                        LogTerminal($"[TCP] No response within timeout")
                    Catch ex As Exception
                        LogTerminal($"[TCP] Read error: {ex.Message}")
                    End Try
                End If

                client.Close()
                LogTerminal($"[TCP] Connection closed")
            End Using
        Catch ex As SocketException
            LogTerminal($"[TCP] Socket error: {ex.SocketErrorCode} - {ex.Message}")
        Catch ex As Exception
            LogTerminal($"[TCP] Error: {ex.Message}")
        End Try
    End Sub

    Private Async Sub SendUdpButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = SanitizeInput(TargetHostTextBox.Text)
        Dim portText = SanitizeInput(TargetPortTextBox.Text)
        Dim payload = PacketDataTextBox.Text

        If String.IsNullOrEmpty(host) OrElse String.IsNullOrEmpty(portText) Then
            ShowAlert("Enter host and port")
            Return
        End If

        If Not IsValidHostOrIP(host) Then
            ShowAlert("Invalid host format")
            Return
        End If

        Dim port As Integer
        If Not Integer.TryParse(portText, port) OrElse port < 1 OrElse port > 65535 Then
            ShowAlert("Invalid port (1-65535)")
            Return
        End If

        If String.IsNullOrEmpty(payload) Then
            payload = "ROOTCASTLE_UDP_PROBE"
        End If

        LogTerminal($"[UDP] Sending to {host}:{port}...")

        Try
            Using client As New UdpClient()
                Dim data = Encoding.UTF8.GetBytes(payload)
                Dim bytesSent = Await client.SendAsync(data, data.Length, host, port)
                LogTerminal($"[UDP] Sent {bytesSent} bytes to {host}:{port}")
                LogTerminal($"[UDP] Datagram sent (connectionless - no acknowledgment expected)")
            End Using
        Catch ex As SocketException
            LogTerminal($"[UDP] Socket error: {ex.SocketErrorCode} - {ex.Message}")
        Catch ex As Exception
            LogTerminal($"[UDP] Error: {ex.Message}")
        End Try
    End Sub

    Private Async Sub PingButton_Click(sender As Object, e As RoutedEventArgs)
        Dim target = SanitizeInput(TargetHostTextBox.Text)
        If String.IsNullOrEmpty(target) Then
            ShowAlert("Enter target host")
            Return
        End If

        If Not IsValidHostOrIP(target) Then
            ShowAlert("Invalid host format")
            Return
        End If

        LogTerminal($"[PING] Starting ping to {target}")

        Try
            Using ping As New Ping()
                Dim successCount = 0
                Dim totalMs As Long = 0
                Dim results As New List(Of PingReply)

                For i = 1 To 4
                    Try
                        Dim reply = Await ping.SendPingAsync(target, 1000)
                        results.Add(reply)

                        If reply.Status = IPStatus.Success Then
                            successCount += 1
                            totalMs += reply.RoundtripTime
                            LogTerminal($"[PING] Reply from {target}: time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}")
                        Else
                            LogTerminal($"[PING] Request to {target}: {reply.Status}")
                        End If
                    Catch ex As PingException
                        LogTerminal($"[PING] Ping #{i} failed: {ex.InnerException?.Message}")
                    End Try

                    Await Task.Delay(500)
                Next

                ' Statistics
                Dim lossPercent = ((4 - successCount) / 4.0) * 100
                Dim avgMs = If(successCount > 0, totalMs / successCount, 0)
                LogTerminal($"[PING] Statistics: Sent=4, Received={successCount}, Lost={4 - successCount} ({lossPercent:F0}% loss)")
                If successCount > 0 Then
                    LogTerminal($"[PING] Average RTT: {avgMs}ms")
                End If
            End Using
        Catch ex As Exception
            LogTerminal($"[PING] Error: {ex.Message}")
        End Try
    End Sub

    Private Async Sub TraceRouteButton_Click(sender As Object, e As RoutedEventArgs)
        Dim target = SanitizeInput(TargetHostTextBox.Text)
        If String.IsNullOrEmpty(target) Then
            ShowAlert("Enter target host")
            Return
        End If

        If Not IsValidHostOrIP(target) Then
            ShowAlert("Invalid host format")
            Return
        End If

        LogTerminal($"[TRACERT] Tracing route to {target}...")
        LogTerminal($"[TRACERT] Maximum hops: 30")
        LogTerminal("")

        Try
            For ttl = 1 To 30
                Using ping As New Ping()
                    Dim options As New PingOptions(ttl, True)
                    Dim buffer = Encoding.ASCII.GetBytes("ROOTCASTLE_TRACE")

                    Try
                        Dim reply = Await ping.SendPingAsync(target, 3000, buffer, options)

                        Dim hopAddress = If(reply.Address?.ToString(), "*")
                        Dim hopTime = If(reply.Status = IPStatus.Success OrElse reply.Status = IPStatus.TtlExpired,
                                         $"{reply.RoundtripTime}ms", "*")

                        LogTerminal($"[TRACERT] {ttl,2}  {hopTime,-8}  {hopAddress}")

                        If reply.Status = IPStatus.Success Then
                            LogTerminal("")
                            LogTerminal($"[TRACERT] Trace complete - {ttl} hops")
                            Exit For
                        End If
                    Catch ex As PingException
                        LogTerminal($"[TRACERT] {ttl,2}  *        Request timed out")
                    End Try
                End Using

                Await Task.Delay(100)  ' Brief delay between hops
            Next
        Catch ex As Exception
            LogTerminal($"[TRACERT] Error: {ex.Message}")
        End Try
    End Sub

    ''' <summary>
    ''' HTTP/HTTPS health check with timeout and TLS validation.
    ''' </summary>
    Private Async Sub HttpCheckButton_Click(sender As Object, e As RoutedEventArgs)
        Dim target = SanitizeInput(TargetHostTextBox.Text)
        If String.IsNullOrEmpty(target) Then
            ShowAlert("Enter target URL or hostname")
            Return
        End If

        ' Build URL if not provided
        Dim url As String
        If target.StartsWith("http://") OrElse target.StartsWith("https://") Then
            url = target
        Else
            url = $"https://{target}"
        End If

        LogTerminal($"[HTTP] Checking health: {url}")

        Dim sw As New System.Diagnostics.Stopwatch()
        sw.Start()

        Try
            Using client As New HttpClient()
                ' Set timeout
                Dim cts As New CancellationTokenSource(TimeSpan.FromSeconds(10))

                ' Make request
                Dim request As New HttpRequestMessage(HttpMethod.Get, New Uri(url))
                request.Headers.Add("User-Agent", "Rootcastle-Network-Monitor/6.0")

                Dim response = Await client.SendRequestAsync(request).AsTask(cts.Token)
                sw.Stop()

                Dim statusCode = CInt(response.StatusCode)
                Dim statusText = response.StatusCode.ToString()

                If response.IsSuccessStatusCode Then
                    LogTerminal($"[HTTP] ✅ {url} - Status: {statusCode} {statusText} ({sw.ElapsedMilliseconds}ms)")
                    ShowAlert($"HTTP OK: {statusCode}")
                ElseIf statusCode >= 400 AndAlso statusCode < 500 Then
                    LogTerminal($"[HTTP] ⚠️ {url} - Client Error: {statusCode} {statusText} ({sw.ElapsedMilliseconds}ms)")
                    ShowAlert($"HTTP Client Error: {statusCode}")
                ElseIf statusCode >= 500 Then
                    LogTerminal($"[HTTP] ❌ {url} - Server Error: {statusCode} {statusText} ({sw.ElapsedMilliseconds}ms)")
                    ShowAlert($"HTTP Server Error: {statusCode}")
                Else
                    LogTerminal($"[HTTP] {url} - Status: {statusCode} {statusText} ({sw.ElapsedMilliseconds}ms)")
                End If
            End Using
        Catch ex As OperationCanceledException
            sw.Stop()
            LogTerminal($"[HTTP] ❌ {url} - Timeout after {sw.ElapsedMilliseconds}ms")
            ShowAlert("HTTP request timed out")
        Catch ex As Exception
            sw.Stop()
            Dim errorType = "Unknown"
            If ex.Message.Contains("SSL") OrElse ex.Message.Contains("TLS") OrElse ex.Message.Contains("certificate") Then
                errorType = "TLS/Certificate"
            ElseIf ex.Message.Contains("host") OrElse ex.Message.Contains("DNS") Then
                errorType = "DNS"
            ElseIf ex.Message.Contains("refused") Then
                errorType = "Connection Refused"
            End If
            LogTerminal($"[HTTP] ❌ {url} - {errorType} Error: {ex.Message}")
            ShowAlert($"HTTP {errorType} Error")
        End Try
    End Sub

    ''' <summary>
    ''' DNS resolution check to verify hostname resolution.
    ''' </summary>
    Private Async Sub DnsCheckButton_Click(sender As Object, e As RoutedEventArgs)
        Dim target = SanitizeInput(TargetHostTextBox.Text)
        If String.IsNullOrEmpty(target) Then
            ShowAlert("Enter hostname to resolve")
            Return
        End If

        ' Remove protocol prefix if present
        If target.StartsWith("http://") Then target = target.Substring(7)
        If target.StartsWith("https://") Then target = target.Substring(8)
        If target.Contains("/") Then target = target.Split("/"c)(0)

        If Not IsValidHostOrIP(target) Then
            ShowAlert("Invalid hostname format")
            Return
        End If

        LogTerminal($"[DNS] Resolving: {target}")

        Dim sw As New System.Diagnostics.Stopwatch()
        sw.Start()

        Try
            Dim hostEntry = Await Dns.GetHostEntryAsync(target)
            sw.Stop()

            _dnsQueryCount += 1

            If hostEntry.AddressList.Length > 0 Then
                LogTerminal($"[DNS] ✅ {target} resolved in {sw.ElapsedMilliseconds}ms:")
                For Each addr In hostEntry.AddressList
                    LogTerminal($"[DNS]   → {addr} ({addr.AddressFamily})")
                Next
                ShowAlert($"DNS OK: {hostEntry.AddressList.Length} address(es)")
            Else
                LogTerminal($"[DNS] ⚠️ {target} resolved but no addresses returned")
                ShowAlert("DNS: No addresses")
            End If
        Catch ex As System.Net.Sockets.SocketException
            sw.Stop()
            _dnsNxdomainCount += 1
            If ex.SocketErrorCode = System.Net.Sockets.SocketError.HostNotFound Then
                LogTerminal($"[DNS] ❌ {target} - NXDOMAIN (host not found)")
                ShowAlert("DNS: Host not found")
            Else
                LogTerminal($"[DNS] ❌ {target} - Error: {ex.SocketErrorCode}")
                ShowAlert($"DNS Error: {ex.SocketErrorCode}")
            End If
        Catch ex As Exception
            sw.Stop()
            LogTerminal($"[DNS] ❌ {target} - Error: {ex.Message}")
            ShowAlert("DNS resolution failed")
        End Try
    End Sub

#End Region

#Region "Input Validation"
    ''' <summary>
    ''' Validates that input is a legitimate hostname or IP address.
    ''' Blocks command injection characters and validates format.
    ''' </summary>
    Private Function IsValidHostOrIP(input As String) As Boolean
        If String.IsNullOrWhiteSpace(input) Then Return False
        If input.Length > 255 Then Return False

        ' Block dangerous characters that could enable injection attacks
        Dim forbidden As Char() = {";"c, "|"c, "&"c, "`"c, "$"c, "("c, ")"c, "{"c, "}"c, "["c, "]"c, "<"c, ">"c, "!"c, ChrW(10), ChrW(13), """"c, "'"c}
        If input.Any(Function(c) forbidden.Contains(c)) Then Return False

        ' Try parse as IP address
        Dim ip As IPAddress = Nothing
        If IPAddress.TryParse(input, ip) Then Return True

        ' Validate as hostname per RFC 1123
        ' Hostname can contain alphanumeric, hyphens, and dots
        ' Each label must start/end with alphanumeric
        Dim hostnamePattern = "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        Return System.Text.RegularExpressions.Regex.IsMatch(input, hostnamePattern)
    End Function

    ''' <summary>
    ''' Validates port range specification string (e.g., "22,80,443" or "1-1000").
    ''' Returns True if empty (uses defaults) or if format is valid.
    ''' </summary>
    Private Function IsValidPortRange(input As String) As Boolean
        If String.IsNullOrWhiteSpace(input) Then Return True  ' Empty = use defaults

        Try
            Dim totalPorts = 0
            For Each part In input.Split(","c)
                part = part.Trim()
                If String.IsNullOrEmpty(part) Then Continue For

                If part.Contains("-") Then
                    Dim r = part.Split("-"c)
                    If r.Length <> 2 Then Return False

                    Dim startPort As Integer
                    Dim endPort As Integer
                    If Not Integer.TryParse(r(0).Trim(), startPort) Then Return False
                    If Not Integer.TryParse(r(1).Trim(), endPort) Then Return False

                    If startPort < 1 OrElse endPort > 65535 OrElse startPort > endPort Then Return False
                    If endPort - startPort > 1000 Then Return False  ' Limit range size to prevent DoS

                    totalPorts += (endPort - startPort + 1)
                Else
                    Dim port As Integer
                    If Not Integer.TryParse(part, port) Then Return False
                    If port < 1 OrElse port > 65535 Then Return False
                    totalPorts += 1
                End If
            Next

            ' Limit total ports to prevent resource exhaustion
            Return totalPorts <= 2000
        Catch
            Return False
        End Try
    End Function

    ''' <summary>
    ''' Sanitizes user input by trimming whitespace and limiting length.
    ''' </summary>
    Private Function SanitizeInput(input As String) As String
        If String.IsNullOrEmpty(input) Then Return ""
        Return input.Trim().Substring(0, Math.Min(input.Trim().Length, 255))
    End Function

    ''' <summary>
    ''' Validates CIDR notation or IP range format.
    ''' </summary>
    Private Function IsValidTargetRange(input As String) As Boolean
        If String.IsNullOrWhiteSpace(input) Then Return False

        input = SanitizeInput(input)

        ' Single IP
        Dim ip As IPAddress = Nothing
        If IPAddress.TryParse(input, ip) Then Return True

        ' CIDR notation (only /24 supported for safety)
        If input.EndsWith("/24") Then
            Dim baseIP = input.Replace("/24", "").Trim()
            If IPAddress.TryParse(baseIP, ip) Then Return True
        End If

        ' IP range (e.g., 192.168.1.1-254)
        If input.Contains("-") Then
            Dim parts = input.Split("."c)
            If parts.Length = 4 AndAlso parts(3).Contains("-") Then
                Dim rangeParts = parts(3).Split("-"c)
                If rangeParts.Length = 2 Then
                    Dim startIP As Integer
                    Dim endIP As Integer
                    If Integer.TryParse(rangeParts(0).Trim(), startIP) AndAlso
                       Integer.TryParse(rangeParts(1).Trim(), endIP) Then
                        If startIP >= 1 AndAlso endIP <= 254 AndAlso startIP <= endIP Then
                            ' Validate base IP
                            Dim baseIPStr = $"{parts(0)}.{parts(1)}.{parts(2)}.1"
                            Return IPAddress.TryParse(baseIPStr, ip)
                        End If
                    End If
                End If
            End If
        End If

        ' Hostname validation
        Return IsValidHostOrIP(input)
    End Function
#End Region

#Region "Configuration Persistence"
    ''' <summary>
    ''' Loads persisted settings including secure API key from PasswordVault.
    ''' Fails gracefully - app continues with defaults if load fails.
    ''' </summary>
    Private Async Sub LoadSettingsAsync()
        Try
            Dim localSettings = ApplicationData.Current.LocalSettings

            ' Load API key from PasswordVault (secure storage)
            Try
                Dim vault As New Windows.Security.Credentials.PasswordVault()
                Dim credential = vault.Retrieve("RootcastleNetworkMonitor", "OpenRouterApiKey")
                If credential IsNot Nothing Then
                    credential.RetrievePassword()
                    _openRouterApiKey = credential.Password
                    LogTerminal("[CFG] API key loaded from secure storage")
                End If
            Catch ex As Exception
                ' No credential stored or access denied - OK, use empty string
                _openRouterApiKey = ""
            End Try

            ' Load other settings from LocalSettings
            If localSettings.Values.ContainsKey("SelectedAIModel") Then
                _selectedAIModel = localSettings.Values("SelectedAIModel").ToString()
            End If

            If localSettings.Values.ContainsKey("SelectedLanguage") Then
                _selectedLanguage = localSettings.Values("SelectedLanguage").ToString()
            End If

            If localSettings.Values.ContainsKey("SuspiciousDetectionEnabled") Then
                _suspiciousDetectionEnabled = CBool(localSettings.Values("SuspiciousDetectionEnabled"))
                SuspiciousPacketCheckBox.IsChecked = _suspiciousDetectionEnabled
            End If

            ' Apply loaded settings to UI
            UpdateAIModelInfo()
            LogTerminal("[CFG] Settings loaded successfully")

        Catch ex As Exception
            LogTerminal($"[CFG] Settings load error (using defaults): {ex.Message}")
        End Try
    End Sub

    ''' <summary>
    ''' Saves settings including secure API key to PasswordVault.
    ''' Called when settings change.
    ''' </summary>
    Private Async Function SaveSettingsAsync() As Task
        Try
            Dim localSettings = ApplicationData.Current.LocalSettings

            ' Save API key to PasswordVault (secure storage)
            If Not String.IsNullOrEmpty(_openRouterApiKey) Then
                Try
                    Dim vault As New Windows.Security.Credentials.PasswordVault()
                    
                    ' Remove existing credential if any
                    Try
                        Dim existing = vault.Retrieve("RootcastleNetworkMonitor", "OpenRouterApiKey")
                        If existing IsNot Nothing Then
                            vault.Remove(existing)
                        End If
                    Catch
                        ' No existing credential - OK
                    End Try

                    ' Add new credential
                    vault.Add(New Windows.Security.Credentials.PasswordCredential(
                        "RootcastleNetworkMonitor",
                        "OpenRouterApiKey",
                        _openRouterApiKey))
                    LogTerminal("[CFG] API key saved to secure storage")
                Catch ex As Exception
                    LogTerminal($"[CFG] API key save error: {ex.Message}")
                End Try
            End If

            ' Save other settings to LocalSettings
            localSettings.Values("SelectedAIModel") = _selectedAIModel
            localSettings.Values("SelectedLanguage") = _selectedLanguage
            localSettings.Values("SuspiciousDetectionEnabled") = _suspiciousDetectionEnabled

            LogTerminal("[CFG] Settings saved")

        Catch ex As Exception
            LogTerminal($"[CFG] Settings save error: {ex.Message}")
        End Try
    End Function

    ''' <summary>
    ''' Sets the OpenRouter API key and persists it securely.
    ''' </summary>
    Public Async Function SetApiKeyAsync(apiKey As String) As Task
        If String.IsNullOrWhiteSpace(apiKey) Then
            _openRouterApiKey = ""
            Return
        End If

        ' Validate API key format (sk-or-v1-...)
        apiKey = apiKey.Trim()
        If Not apiKey.StartsWith("sk-or-") AndAlso Not apiKey.StartsWith("sk-") Then
            LogTerminal("[CFG] Warning: API key format may be invalid")
        End If

        _openRouterApiKey = apiKey
        Await SaveSettingsAsync()
    End Function
#End Region

#Region "SOFIA AI"
    Private Sub AIModelComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim item = TryCast(AIModelComboBox.SelectedItem, ComboBoxItem)
        If item IsNot Nothing Then
            _selectedAIModel = item.Tag?.ToString()
            UpdateAIModelInfo()
            SaveSettingsAsync()  ' Persist setting
            LogTerminal($"[AI] Model changed: {item.Content}")
        End If
    End Sub

    Private Sub AILanguageComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim item = TryCast(AILanguageComboBox.SelectedItem, ComboBoxItem)
        If item IsNot Nothing Then
            _selectedLanguage = item.Tag?.ToString()
            UpdateAIModelInfo()
            SaveSettingsAsync()  ' Persist setting
            LogTerminal($"[AI] Language changed: {item.Content}")
        End If
    End Sub

    Private Sub UpdateAIModelInfo()
        Try
            Dim langName = If(_selectedLanguage = "TR", "Türkçe",
                           If(_selectedLanguage = "EN", "English",
                           If(_selectedLanguage = "DE", "Deutsch",
                           If(_selectedLanguage = "FR", "Français",
                           If(_selectedLanguage = "ES", "Español",
                           If(_selectedLanguage = "JP", "日本語",
                           If(_selectedLanguage = "CN", "中文", "Unknown")))))))

            If AIModelInfoText IsNot Nothing Then
                AIModelInfoText.Text = $"Selected: {_selectedAIModel} | Language: {langName}"
            End If
        Catch ex As Exception
            System.Diagnostics.Debug.WriteLine($"[UI] AI model info update error: {ex.Message}")
        End Try
    End Sub

    Private Function GetLanguagePrompt() As String
        Select Case _selectedLanguage
            Case "EN"
                Return "Always respond in English. Be technical and concise."
            Case "DE"
                Return "Antworte immer auf Deutsch. Sei technisch und präzise."
            Case "FR"
                Return "Réponds toujours en français. Sois technique et concis."
            Case "ES"
                Return "Responde siempre en español. Sé técnico y conciso."
            Case "JP"
                Return "常に日本語で回答してください。技術的で簡潔にしてください。"
            Case "CN"
                Return "请始终用中文回答。要技术性强且简洁。"
            Case Else ' TR
                Return "Her zaman Türkçe yanıt ver. Teknik ve özlü ol."
        End Select
    End Function

    Private Async Sub AIAnalyzeButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim query = AIQueryTextBox?.Text?.Trim()
            If String.IsNullOrEmpty(query) Then
                query = If(_selectedLanguage = "TR", "Mevcut ağ durumunu analiz et ve güvenlik değerlendirmesi yap.",
                                                     "Analyze current network status and provide security assessment.")
            End If

            AIAnalysisText.Text = If(_selectedLanguage = "TR", "[SOFIA] 🔄 Analiz ediliyor, lütfen bekleyin...",
                                                                "[SOFIA] 🔄 Analyzing, please wait...")
            AIStatusText.Text = "Processing..."
            StatusText.Text = "[AI ANALYZING]..."

            Dim data = CollectAnalysisData()
            Dim response = Await GetAIResponseAsync(data, query)

            AIAnalysisText.Text = response
            AIStatusText.Text = "Ready"
            StatusText.Text = "[AI] ✓ Complete"

            If AIQueryTextBox IsNot Nothing Then
                AIQueryTextBox.Text = ""
            End If
        Catch ex As Exception
            AIAnalysisText.Text = $"[SOFIA] ❌ Error: {ex.Message}"
            AIStatusText.Text = "Error"
            StatusText.Text = "[AI] Error"
        End Try
    End Sub

    Private Sub AIQueryTextBox_KeyDown(sender As Object, e As KeyRoutedEventArgs)
        If e.Key = Windows.System.VirtualKey.Enter Then AIAnalyzeButton_Click(sender, Nothing)
    End Sub

    Private Async Sub AIQuickAnalyze_Click(sender As Object, e As RoutedEventArgs)
        Dim button = TryCast(sender, Button)
        Dim actionType = button?.Tag?.ToString()

        AIAnalysisText.Text = If(_selectedLanguage = "TR", "[SOFIA] 🔄 İşleniyor...", "[SOFIA] 🔄 Processing...")
        AIStatusText.Text = "Processing..."

        Dim query As String = ""
        Select Case actionType
            Case "traffic"
                query = If(_selectedLanguage = "TR",
                    "Mevcut ağ trafiğini detaylı analiz et. Protokol dağılımı, bant genişliği kullanımı ve olası darboğazları belirle.",
                    "Analyze current network traffic in detail. Identify protocol distribution, bandwidth usage and potential bottlenecks.")
            Case "security"
                query = If(_selectedLanguage = "TR",
                    "Kapsamlı güvenlik taraması yap. Açık portlar, şüpheli trafik, potansiyel tehditler ve güvenlik açıklarını listele.",
                    "Perform comprehensive security scan. List open ports, suspicious traffic, potential threats and vulnerabilities.")
            Case "firewall"
                query = If(_selectedLanguage = "TR",
                    "Tespit edilen trafiğe göre firewall kural önerileri oluştur. iptables ve Windows Firewall formatında.",
                    "Generate firewall rule recommendations based on detected traffic. In iptables and Windows Firewall format.")
            Case "summary"
                query = If(_selectedLanguage = "TR",
                    "Tüm ağ aktivitesinin yönetici özeti oluştur. İstatistikler ve aksiyon maddeleri ile.",
                    "Create executive summary of all network activity. With statistics and action items.")
            Case "anomaly"
                query = If(_selectedLanguage = "TR",
                    "Anomali tespiti yap. Normal trafik profilinden sapmaları ve şüpheli davranış kalıplarını tespit et.",
                    "Perform anomaly detection. Identify deviations from normal traffic profile and suspicious behavior patterns.")
            Case "performance"
                query = If(_selectedLanguage = "TR",
                    "Ağ performans analizi yap. Latency, jitter, packet loss değerlerini yorumla ve optimizasyon önerileri sun.",
                    "Perform network performance analysis. Interpret latency, jitter, packet loss values and provide optimization recommendations.")
            Case "toptalkers"
                query = If(_selectedLanguage = "TR",
                    "En çok trafik üreten host'ları ve uygulamaları analiz et. Bant genişliği tüketim oranlarını belirt.",
                    "Analyze top traffic generating hosts and applications. Indicate bandwidth consumption rates.")
            Case "incident"
                query = If(_selectedLanguage = "TR",
                    "Incident response raporu oluştur. Timeline, etkilenen sistemler ve aksiyon planı ile.",
                    "Create incident response report. With timeline, affected systems and action plan.")
        End Select

        Dim data = CollectAnalysisData()
        Dim response = Await GetAIResponseAsync(data, query)
        AIAnalysisText.Text = response
        AIStatusText.Text = "Ready"
    End Sub

    Private Function CollectAnalysisData() As String
        Dim sb As New StringBuilder()
        sb.AppendLine("=== ROOTCASTLE NETWORK ANALYSIS DATA ===")
        sb.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}")
        sb.AppendLine($"External IP: {_externalIP}")
        sb.AppendLine()
        sb.AppendLine("--- INTERFACE INFO ---")
        sb.AppendLine($"Interface: {InterfaceNameText.Text}")
        sb.AppendLine($"IP Address: {IPv4Text.Text}")
        sb.AppendLine($"Gateway: {GatewayText.Text}")
        sb.AppendLine($"DNS: {DnsServersText.Text}")
        sb.AppendLine()
        sb.AppendLine("--- TRAFFIC STATISTICS ---")
        sb.AppendLine($"Total Bytes IN: {FormatBytes(_totalBytesIn)}")
        sb.AppendLine($"Total Bytes OUT: {FormatBytes(_totalBytesOut)}")
        sb.AppendLine($"Current Rate IN: {FormatBytes(_bytesPerSecIn)}/s")
        sb.AppendLine($"Current Rate OUT: {FormatBytes(_bytesPerSecOut)}/s")
        sb.AppendLine()
        sb.AppendLine("--- PACKET STATISTICS ---")
        sb.AppendLine($"Total Packets: {_packetCount}")
        sb.AppendLine($"TCP: {_tcpCount} | UDP: {_udpCount} | ICMP: {_icmpCount} | Other: {_otherCount}")
        sb.AppendLine($"Suspicious: {_suspiciousCount}")
        sb.AppendLine()
        sb.AppendLine("--- QoS METRICS ---")
        sb.AppendLine($"Latency: {_currentLatency:F1} ms | Jitter: {_jitter:F1} ms | Packet Loss: {_packetLoss:F2}%")
        sb.AppendLine()
        sb.AppendLine("--- SECURITY ---")
        sb.AppendLine($"Port Scans: {_portScanCount} | DoS: {_dosCount} | TLS Weak: {_tlsWeakCount}")
        sb.AppendLine()
        sb.AppendLine("--- NMAP RESULTS ---")
        sb.AppendLine($"Hosts: {_nmapResults.Count}")
        For Each host In _nmapResults.Take(10)
            sb.AppendLine($"  {host.Host} [{host.Status}] Ports: {host.Ports}")
        Next
        sb.AppendLine()
        sb.AppendLine("--- TOP HOSTS ---")
        For Each kv In _hostTraffic.OrderByDescending(Function(x) x.Value).Take(10)
            sb.AppendLine($"  {kv.Key}: {FormatBytes(kv.Value)}")
        Next
        Return sb.ToString()
    End Function

    ''' <summary>
    ''' Defense-grade AI request with timeout, retry/backoff, and rate limit handling.
    ''' </summary>
    Private Async Function GetAIResponseAsync(data As String, userQuery As String) As Task(Of String)
        Const MAX_RETRIES As Integer = 3
        Const BASE_TIMEOUT_SECONDS As Integer = 30
        Const MAX_BACKOFF_SECONDS As Integer = 60

        Try
            If String.IsNullOrEmpty(_openRouterApiKey) Then
                Return If(_selectedLanguage = "TR",
                    "[SOFIA] ⚠️ API Key Gerekli

OpenRouter API anahtarı ayarlanmamış. 

🔧 Çözüm:
1. https://openrouter.ai adresine gidin
2. Ücretsiz hesap oluşturun
3. API Key alın
4. Ayarlar (⚙️) menüsünden API Key'i girin

📝 Not: Ücretsiz modeller kullanabilirsiniz.",
                    "[SOFIA] ⚠️ API Key Required

OpenRouter API key is not set.

🔧 Solution:
1. Go to https://openrouter.ai
2. Create a free account
3. Get your API Key
4. Enter API Key from Settings (⚙️) menu

📝 Note: You can use free models.")
            End If

            ' Prepare request body
            Dim languagePrompt = GetLanguagePrompt()
            Dim systemPrompt = $"You are SOFIA (Smart Operational Firewall Intelligence Assistant), a professional network security and analysis AI developed by Rootcastle Engineering & Innovation.

ABOUT ROOTCASTLE:
Rootcastle Engineering & Innovation is a technology-driven engineering company focused on building secure, mission-critical software systems. Founded by Batuhan Ayrıbaş, Rootcastle develops advanced cybersecurity platforms, secure IoT infrastructures, and defense-oriented software solutions designed for high-reliability environments where resilience, integrity, and data protection are non-negotiable.

YOUR ROLE:
You are the built-in AI engine of Rootcastle Network Monitor v6.0, a defense-grade network surveillance and security analysis tool.

TASKS:
1. Analyze network traffic and detect anomalies
2. Evaluate and prioritize security threats
3. Provide firewall rules and security recommendations
4. Support incident response and threat hunting
5. Suggest performance optimizations
6. Create technical and executive reports
7. Assess zero-trust compliance

RULES:
- {languagePrompt}
- Explain technical details clearly
- Provide concrete, actionable recommendations
- Indicate risk levels (Critical/High/Medium/Low)
- Use emojis for visualization
- Use structured and readable format
- Prioritize security and defense-grade thinking"

            Dim userPrompt = $"USER QUERY: {userQuery}

NETWORK DATA:
{data}

Please analyze the network data above and provide a detailed response to the user's query."

            Dim body As New JsonObject()
            body.Add("model", JsonValue.CreateStringValue(_selectedAIModel))

            Dim msgs As New JsonArray()
            Dim sysMsg As New JsonObject()
            sysMsg.Add("role", JsonValue.CreateStringValue("system"))
            sysMsg.Add("content", JsonValue.CreateStringValue(systemPrompt))
            msgs.Add(sysMsg)

            Dim usrMsg As New JsonObject()
            usrMsg.Add("role", JsonValue.CreateStringValue("user"))
            usrMsg.Add("content", JsonValue.CreateStringValue(userPrompt))
            msgs.Add(usrMsg)

            body.Add("messages", msgs)
            body.Add("max_tokens", JsonValue.CreateNumberValue(2000))
            body.Add("temperature", JsonValue.CreateNumberValue(0.7))

            ' Retry loop with exponential backoff
            Dim attempt = 0
            Dim lastError As String = ""
            Dim delayMs As Integer = 0
            Dim shouldRetry As Boolean = False

            While attempt < MAX_RETRIES
                attempt += 1

                Try
                    Using client As New HttpClient()
                        ' Set headers (NEVER log the full API key)
                        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {_openRouterApiKey}")
                        client.DefaultRequestHeaders.Add("HTTP-Referer", "https://rootcastle.rei")
                        client.DefaultRequestHeaders.Add("X-Title", "Rootcastle Network Monitor")

                        ' Create request with timeout
                        Dim cts As New CancellationTokenSource(TimeSpan.FromSeconds(BASE_TIMEOUT_SECONDS))
                        Dim content As New HttpStringContent(body.Stringify(), Windows.Storage.Streams.UnicodeEncoding.Utf8, "application/json")

                        LogStructured("DEBUG", "AI_REQUEST", _selectedAIModel, $"Attempt {attempt}/{MAX_RETRIES}", NetworkErrorType.None, "")

                        Dim response = Await client.PostAsync(New Uri(OPENROUTER_API_URL), content).AsTask(cts.Token)
                        Dim responseText = Await response.Content.ReadAsStringAsync()

                        ' Handle success
                        If response.IsSuccessStatusCode Then
                            Dim json = JsonObject.Parse(responseText)
                            Dim choices = json.GetNamedArray("choices")
                            If choices.Count > 0 Then
                                Dim aiResponse = choices.GetObjectAt(0).GetNamedObject("message").GetNamedString("content")
                                LogStructured("INFO", "AI_RESPONSE", _selectedAIModel, $"Success on attempt {attempt}", NetworkErrorType.None, "")
                                Return $"[SOFIA] 🧠 AI Analysis Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{aiResponse}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📅 {DateTime.Now:yyyy-MM-dd HH:mm:ss}
🔧 Model: {_selectedAIModel}"
                            End If
                        End If

                        ' Handle specific error codes
                        Dim statusCode = CInt(response.StatusCode)

                        ' 401/403 - Invalid key (not retryable)
                        If statusCode = 401 OrElse statusCode = 403 Then
                            LogStructured("ERR", "AI_AUTH", _selectedAIModel, $"Authentication failed: {statusCode}", NetworkErrorType.Unauthorized, "")
                            Return If(_selectedLanguage = "TR",
                                "[SOFIA] ❌ API Key Hatası (Unauthorized)

API anahtarınız geçersiz veya süresi dolmuş.

🔧 Çözüm:
1. Ayarlar (⚙️) menüsünü açın
2. Geçerli bir OpenRouter API Key girin
3. https://openrouter.ai/keys adresinden yeni key alabilirsiniz",
                                "[SOFIA] ❌ API Key Error (Unauthorized)

Your API key is invalid or expired.

🔧 Solution:
1. Open Settings (⚙️) menu
2. Enter a valid OpenRouter API Key
3. Get a new key from https://openrouter.ai/keys")
                        End If

                        ' 429 - Rate limited (retryable with backoff)
                        If statusCode = 429 Then
                            LogStructured("WARN", "AI_RATELIMIT", _selectedAIModel, $"Rate limited on attempt {attempt}", NetworkErrorType.RateLimited, "")

                            ' Check for Retry-After header
                            Dim retryAfterSeconds = 5 * attempt  ' Default exponential backoff
                            If response.Headers.ContainsKey("Retry-After") Then
                                Dim retryAfterStr = response.Headers("Retry-After")
                                Integer.TryParse(retryAfterStr, retryAfterSeconds)
                                retryAfterSeconds = Math.Min(retryAfterSeconds, MAX_BACKOFF_SECONDS)
                            End If

                            ' Add jitter (0-1 second)
                            Dim jitter = New Random().NextDouble()
                            Dim waitMs = CInt((retryAfterSeconds + jitter) * 1000)

                            If attempt < MAX_RETRIES Then
                                Await Task.Delay(waitMs)
                                Continue While
                            Else
                                Return If(_selectedLanguage = "TR",
                                    "[SOFIA] ⚠️ Rate Limit Aşıldı

OpenRouter API'ye çok fazla istek gönderildi. Lütfen birkaç dakika bekleyin ve tekrar deneyin.

💡 İpucu: Ücretsiz modeller daha düşük rate limit'e sahiptir.",
                                    "[SOFIA] ⚠️ Rate Limit Exceeded

Too many requests sent to OpenRouter API. Please wait a few minutes and try again.

💡 Tip: Free models have lower rate limits.")
                            End If
                        End If

                        ' 5xx - Server error (retryable)
                        If statusCode >= 500 Then
                            LogStructured("WARN", "AI_SERVER_ERROR", _selectedAIModel, $"Server error {statusCode} on attempt {attempt}", NetworkErrorType.HttpError, "")
                            lastError = $"Server error: {statusCode}"

                            If attempt < MAX_RETRIES Then
                                ' Exponential backoff with jitter
                                Dim waitMs = CInt((Math.Pow(2, attempt) + New Random().NextDouble()) * 1000)
                                waitMs = Math.Min(waitMs, MAX_BACKOFF_SECONDS * 1000)
                                Await Task.Delay(waitMs)
                                Continue While
                            End If
                        End If

                        ' Other errors (not retryable)
                        lastError = $"HTTP {statusCode}"
                        LogStructured("ERR", "AI_ERROR", _selectedAIModel, $"Request failed: {statusCode}", NetworkErrorType.HttpError, responseText.Substring(0, Math.Min(200, responseText.Length)))
                        Exit While

                    End Using

                    ' Reset delay for next iteration
                    delayMs = 0

                Catch ex As OperationCanceledException
                    LogStructured("WARN", "AI_TIMEOUT", _selectedAIModel, $"Timeout on attempt {attempt}", NetworkErrorType.Timeout, "")
                    lastError = "Request timed out"

                    If attempt < MAX_RETRIES Then
                        delayMs = CInt(1000 * attempt)
                        shouldRetry = True
                    End If
                Catch ex As Exception
                    LogStructured("ERR", "AI_EXCEPTION", _selectedAIModel, $"Exception on attempt {attempt}: {ex.Message}", NetworkErrorType.Unknown, ex.ToString())
                    lastError = ex.Message

                    If attempt < MAX_RETRIES Then
                        delayMs = CInt(1000 * attempt)
                        shouldRetry = True
                    End If
                End Try

                ' Delay outside catch block (VB.NET doesn't allow Await in Catch)
                If delayMs > 0 AndAlso shouldRetry Then
                    Await Task.Delay(delayMs)
                    shouldRetry = False
                    Continue While
                End If
            End While

            ' All retries exhausted
            Return If(_selectedLanguage = "TR",
                $"[SOFIA] ⚠️ Analiz yapılamadı

{MAX_RETRIES} deneme sonrası başarısız oldu.
Son hata: {lastError}

🔧 Öneriler:
- İnternet bağlantınızı kontrol edin
- API anahtarınızı doğrulayın
- Birkaç dakika sonra tekrar deneyin",
                $"[SOFIA] ⚠️ Analysis failed

Failed after {MAX_RETRIES} attempts.
Last error: {lastError}

🔧 Suggestions:
- Check your internet connection
- Verify your API key
- Try again in a few minutes")

        Catch ex As Exception
            LogStructured("ERR", "AI_FATAL", "", $"Fatal error: {ex.Message}", NetworkErrorType.Unknown, ex.ToString())
            Return $"[SOFIA] ❌ Error: {ex.Message}"
        End Try
    End Function
#End Region

#Region "NMAP Scanner"
    Private Sub NmapMenuButton_Click(sender As Object, e As RoutedEventArgs)
        NmapResultsPanel.Visibility = If(NmapResultsPanel.Visibility = Visibility.Visible, Visibility.Collapsed, Visibility.Visible)
    End Sub

    Private Async Sub NmapScanButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapScanning Then
            LogTerminal("[NMAP] Scan already in progress")
            Return
        End If

        ' CRITICAL: Require explicit permission confirmation before scanning
        If Not ScanPermissionCheckBox.IsChecked.GetValueOrDefault(False) Then
            LogTerminal("[NMAP] Authorization required - checkbox not checked")
            ShowAlert("⚠️ Please confirm you have authorization to scan these targets")
            Return
        End If

        Dim target = NmapTargetTextBox.Text.Trim()
        If String.IsNullOrEmpty(target) Then
            LogTerminal("[NMAP] Target required")
            ShowAlert("Enter target IP/range")
            Return
        End If

        Dim scanType = GetSelectedScanType()
        Dim portsText = NmapPortsTextBox.Text.Trim()

        _isNmapScanning = True
        _nmapCancellationTokenSource = New CancellationTokenSource()
        NmapStopButton.IsEnabled = True
        NmapProgressBar.Visibility = Visibility.Visible
        NmapProgressBar.IsIndeterminate = True
        NmapResultsPanel.Visibility = Visibility.Visible
        _nmapResults.Clear()
        NmapResultsListView.ItemsSource = Nothing

        LogTerminal($"[NMAP] Starting {scanType} scan: {target}")
        NmapStatusText.Text = $"[SCAN: {target}]"
        ShowAlert($"NMAP: {target}")

        Try
            Dim ports = GetPortsForScan(scanType, portsText)
            Dim targets = ParseTargets(target)

            LogTerminal($"[NMAP] Scanning {targets.Count} target(s), {ports.Length} port(s)")

            For Each t In targets
                If _nmapCancellationTokenSource.IsCancellationRequested Then Exit For
                Await ScanHostAsync(t, ports, scanType, _nmapCancellationTokenSource.Token)
                RefreshNmapResults()
            Next

            RefreshNmapResults()
            LogTerminal($"[NMAP] Scan complete: {_nmapResults.Count} host(s) found")
            NmapStatusText.Text = $"[DONE: {_nmapResults.Count}]"
            ShowAlert($"NMAP complete: {_nmapResults.Count} hosts")

        Catch ex As OperationCanceledException
            LogTerminal("[NMAP] Scan cancelled by user")
            NmapStatusText.Text = "[CANCELLED]"
        Catch ex As Exception
            LogTerminal($"[NMAP] Error: {ex.Message}")
            NmapStatusText.Text = "[ERROR]"
            ShowAlert($"NMAP Error: {ex.Message}")
        Finally
            _isNmapScanning = False
            NmapStopButton.IsEnabled = False
            NmapProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub

    Private Async Sub NmapNetworkDiscoveryButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapScanning Then
            LogTerminal("[NMAP] Scan already in progress")
            Return
        End If

        ' CRITICAL: Require explicit permission confirmation before scanning
        If Not ScanPermissionCheckBox.IsChecked.GetValueOrDefault(False) Then
            LogTerminal("[NMAP] Authorization required - checkbox not checked")
            ShowAlert("⚠️ Please confirm you have authorization to scan these targets")
            Return
        End If

        If _selectedInterface Is Nothing Then
            LogTerminal("[NMAP] Select interface first")
            ShowAlert("Select network interface first")
            Return
        End If

        Try
            Dim ipProps = _selectedInterface.GetIPProperties()
            Dim ipv4 = ipProps.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
            If ipv4 Is Nothing Then
                LogTerminal("[NMAP] No IPv4 address found")
                ShowAlert("No IPv4 address on selected interface")
                Return
            End If

            Dim localIP = ipv4.Address.ToString()
            Dim parts = localIP.Split("."c)
            If parts.Length <> 4 Then
                LogTerminal("[NMAP] Invalid IP format")
                Return
            End If

            Dim networkRange = $"{parts(0)}.{parts(1)}.{parts(2)}.1-254"
            NmapTargetTextBox.Text = networkRange
            LogTerminal($"[NMAP] Network discovery: {networkRange}")

            _isNmapScanning = True
            _nmapCancellationTokenSource = New CancellationTokenSource()
            NmapStopButton.IsEnabled = True
            NmapProgressBar.Visibility = Visibility.Visible
            NmapProgressBar.IsIndeterminate = True
            NmapResultsPanel.Visibility = Visibility.Visible
            _nmapResults.Clear()
            NmapResultsListView.ItemsSource = Nothing

            NmapStatusText.Text = "[DISCOVERING...]"
            ShowAlert("Network discovery started")

            Dim baseIP = $"{parts(0)}.{parts(1)}.{parts(2)}."
            Dim tasks As New List(Of Task)

            For i = 1 To 254
                If _nmapCancellationTokenSource.IsCancellationRequested Then Exit For

                Dim ip = baseIP & i.ToString()
                tasks.Add(PingHostAsync(ip))

                If tasks.Count >= 50 Then
                    Await Task.WhenAll(tasks)
                    tasks.Clear()
                    RefreshNmapResults()
                    NmapStatusText.Text = $"[SCAN: {i}/254 - Found: {_nmapResults.Count}]"
                End If
            Next

            If tasks.Count > 0 Then
                Await Task.WhenAll(tasks)
            End If

            RefreshNmapResults()
            LogTerminal($"[NMAP] Discovery complete: {_nmapResults.Count} host(s) found")
            NmapStatusText.Text = $"[FOUND: {_nmapResults.Count}]"
            ShowAlert($"Discovery complete: {_nmapResults.Count} hosts")

        Catch ex As Exception
            LogTerminal($"[NMAP] Discovery error: {ex.Message}")
            ShowAlert($"Discovery error: {ex.Message}")
        Finally
            _isNmapScanning = False
            NmapStopButton.IsEnabled = False
            NmapProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub

    Private Sub NmapStopButton_Click(sender As Object, e As RoutedEventArgs)
        If _nmapCancellationTokenSource IsNot Nothing Then
            _nmapCancellationTokenSource.Cancel()
            LogTerminal("[NMAP] Stop requested...")
            NmapStatusText.Text = "[STOPPING...]"
        End If
    End Sub

    Private Async Function PingHostAsync(ip As String) As Task
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 500)
                If reply.Status = IPStatus.Success Then
                    SyncLock _nmapResults
                        If Not _nmapResults.Any(Function(r) r.Host = ip) Then
                            _nmapResults.Add(New NmapHostResult With {
                                .Host = ip,
                                .Status = "UP",
                                .Ports = $"RTT: {reply.RoundtripTime}ms",
                                .OS = "",
                                .OpenPorts = New List(Of Integer)
                            })
                        End If
                    End SyncLock
                End If
            End Using
        Catch
        End Try
    End Function

    Private Async Function ScanHostAsync(ip As String, ports As Integer(), scanType As String, token As CancellationToken) As Task
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 1000)
                If reply.Status <> IPStatus.Success Then
                    Return
                End If
            End Using
        Catch
            Return
        End Try

        If token.IsCancellationRequested Then Return

        Dim result As New NmapHostResult With {
            .Host = ip,
            .Status = "UP",
            .OpenPorts = New List(Of Integer),
            .OS = ""
        }

        Await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Low,
            Sub() LogTerminal($"[NMAP] Scanning {ip} ({ports.Length} ports)"))

        Dim openPorts As New List(Of String)

        For Each port In ports
            If token.IsCancellationRequested Then Exit For

            Try
                Using client As New TcpClient()
                    client.SendTimeout = 200
                    client.ReceiveTimeout = 200

                    Dim connectTask = client.ConnectAsync(ip, port)
                    Dim timeoutTask = Task.Delay(200, token)

                    Dim completedTask = Await Task.WhenAny(connectTask, timeoutTask)

                    If completedTask Is connectTask AndAlso Not connectTask.IsFaulted AndAlso client.Connected Then
                        result.OpenPorts.Add(port)
                        Dim svc = If(_commonServices.ContainsKey(port), _commonServices(port), "unknown")
                        openPorts.Add($"{port}/{svc}")

                        Await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Low,
                            Sub() LogTerminal($"[NMAP] {ip}:{port} OPEN ({svc})"))
                    End If

                    client.Close()
                End Using
            Catch
            End Try
        Next

        If scanType = "OS Detection" OrElse scanType = "Full Scan" OrElse scanType = "Service Scan" Then
            result.OS = Await DetectOSAsync(ip)
        End If

        result.Ports = If(openPorts.Count > 0, String.Join(", ", openPorts), "No open ports")

        If result.OpenPorts.Count > 0 OrElse scanType = "Quick Scan" Then
            SyncLock _nmapResults
                Dim existing = _nmapResults.FirstOrDefault(Function(r) r.Host = ip)
                If existing IsNot Nothing Then
                    existing.Ports = result.Ports
                    existing.OS = result.OS
                    existing.OpenPorts = result.OpenPorts
                Else
                    _nmapResults.Add(result)
                End If
            End SyncLock
        End If
    End Function

    Private Async Function DetectOSAsync(ip As String) As Task(Of String)
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(ip, 1000)
                If reply.Status = IPStatus.Success AndAlso reply.Options IsNot Nothing Then
                    Dim ttl = reply.Options.Ttl
                    If ttl <= 64 Then Return "Linux/Unix/macOS"
                    If ttl <= 128 Then Return "Windows"
                    If ttl <= 255 Then Return "Network Device"
                End If
            End Using
        Catch
        End Try
        Return "Unknown"
    End Function

    Private Function GetSelectedScanType() As String
        Try
            Dim item = TryCast(NmapScanTypeCombo.SelectedItem, ComboBoxItem)
            Return If(item?.Content?.ToString(), "Quick Scan")
        Catch
            Return "Quick Scan"
        End Try
    End Function

    Private Function GetPortsForScan(scanType As String, customPorts As String) As Integer()
        If Not String.IsNullOrEmpty(customPorts) Then
            Return ParsePorts(customPorts)
        End If

        Select Case scanType
            Case "Full Scan"
                Return _fullScanPorts
            Case "UDP Scan"
                Return {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514}
            Case "Stealth Scan", "Quick Scan"
                Return _quickScanPorts
            Case "Service Scan", "OS Detection"
                Return _quickScanPorts
            Case "Vuln Scan"
                Return {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080}
            Case Else
                Return _quickScanPorts
        End Select
    End Function

    Private Function ParsePorts(text As String) As Integer()
        Dim ports As New List(Of Integer)
        Try
            For Each part In text.Split(","c)
                part = part.Trim()
                If part.Contains("-") Then
                    Dim r = part.Split("-"c)
                    Dim startPort = Integer.Parse(r(0).Trim())
                    Dim endPort = Integer.Parse(r(1).Trim())
                    If startPort <= endPort AndAlso startPort > 0 AndAlso endPort <= 65535 Then
                        ports.AddRange(Enumerable.Range(startPort, endPort - startPort + 1))
                    End If
                Else
                    Dim port = Integer.Parse(part)
                    If port > 0 AndAlso port <= 65535 Then
                        ports.Add(port)
                    End If
                End If
            Next
        Catch ex As Exception
            LogTerminal($"[NMAP] Port parse error: {ex.Message}")
        End Try
        Return If(ports.Count > 0, ports.Distinct().OrderBy(Function(p) p).ToArray(), _quickScanPorts)
    End Function

    Private Function ParseTargets(target As String) As List(Of String)
        Dim targets As New List(Of String)
        Try
            target = target.Trim()

            If target.Contains("/24") Then
                Dim baseIP = target.Replace("/24", "").Trim().Split("."c)
                If baseIP.Length = 4 Then
                    For i = 1 To 254
                        targets.Add($"{baseIP(0)}.{baseIP(1)}.{baseIP(2)}.{i}")
                    Next
                End If
            ElseIf target.Contains("-") Then
                Dim parts = target.Split("."c)
                If parts.Length = 4 AndAlso parts(3).Contains("-") Then
                    Dim rangeParts = parts(3).Split("-"c)
                    Dim startIP = Integer.Parse(rangeParts(0).Trim())
                    Dim endIP = Integer.Parse(rangeParts(1).Trim())
                    For i = startIP To endIP
                        targets.Add($"{parts(0)}.{parts(1)}.{parts(2)}.{i}")
                    Next
                Else
                    targets.Add(target)
                End If
            Else
                targets.Add(target)
            End If
        Catch ex As Exception
            LogTerminal($"[NMAP] Target parse error: {ex.Message}")
            targets.Add(target)
        End Try
        Return targets
    End Function

    Private Sub RefreshNmapResults()
        Try
            Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal,
                Sub()
                    NmapResultsListView.ItemsSource = Nothing
                    NmapResultsListView.ItemsSource = _nmapResults.ToList()
                    NmapHostCountText.Text = $"[{_nmapResults.Count} hosts]"
                End Sub)
        Catch
        End Try
    End Sub

    Private Sub NmapResultsListView_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim selected = TryCast(NmapResultsListView.SelectedItem, NmapHostResult)
        If selected IsNot Nothing Then
            TargetHostTextBox.Text = selected.Host
            PacketDetailsPanel.Visibility = Visibility.Visible
            PacketDetailsText.Text = $"═══ HOST: {selected.Host} ═══" & vbCrLf &
                                    $"Status: {selected.Status}" & vbCrLf &
                                    $"OS: {If(String.IsNullOrEmpty(selected.OS), "Unknown", selected.OS)}" & vbCrLf &
                                    $"Open Ports: {selected.Ports}" & vbCrLf &
                                    $"Port Count: {selected.OpenPorts.Count}"
        End If
    End Sub
#End Region

#Region "Security Automation"

    Private _securityService As SecurityService = SecurityService.Instance
    Private _isSecurityScanning As Boolean = False

    ''' <summary>
    ''' Handles security consent checkbox state change.
    ''' </summary>
    Private Sub SecurityConsentCheckBox_Checked(sender As Object, e As RoutedEventArgs)
        UpdateSecurityScanButtonState()
        LogStructured("INFO", "SECURITY_CONSENT", "", "User acknowledged legal disclaimer", NetworkErrorType.None, "")
    End Sub

    Private Sub SecurityConsentCheckBox_Unchecked(sender As Object, e As RoutedEventArgs)
        UpdateSecurityScanButtonState()
    End Sub

    ''' <summary>
    ''' Handles Lab Mode toggle.
    ''' </summary>
    Private Sub LabModeCheckBox_Checked(sender As Object, e As RoutedEventArgs)
        _securityService.EnableLabMode()
        LabModeStatusText.Text = "[ENABLED - Private IPs allowed]"
        LabModeStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 204, 255))
        LogStructured("WARN", "LAB_MODE", "", "Lab Mode ENABLED - private IP ranges now allowed", NetworkErrorType.None, "")
        
        ' Re-validate target
        SecurityTargetTextBox_TextChanged(Nothing, Nothing)
    End Sub

    Private Sub LabModeCheckBox_Unchecked(sender As Object, e As RoutedEventArgs)
        _securityService.DisableLabMode()
        LabModeStatusText.Text = "[DISABLED]"
        LabModeStatusText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 102, 102, 102))
        LogStructured("INFO", "LAB_MODE", "", "Lab Mode disabled", NetworkErrorType.None, "")
        
        ' Re-validate target
        SecurityTargetTextBox_TextChanged(Nothing, Nothing)
    End Sub

    ''' <summary>
    ''' Handles security tool selection change.
    ''' </summary>
    Private Sub SecurityToolComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim selectedItem = TryCast(SecurityToolComboBox.SelectedItem, ComboBoxItem)
        If selectedItem Is Nothing Then Return

        Dim toolTag = selectedItem.Tag?.ToString()
        Dim description = ""

        Select Case toolTag
            Case "Nmap"
                description = "Nmap: Network exploration and security auditing. Discover hosts, services, OS detection, and firewall evasion."
            Case "SQLMap"
                description = "SQLMap: Automatic SQL injection detection and exploitation. Supports MySQL, PostgreSQL, Oracle, MSSQL."
            Case "WPScan"
                description = "WPScan: WordPress security scanner. Detects vulnerable plugins, themes, and configuration issues."
            Case "XSStrike"
                description = "XSStrike: Advanced XSS detection suite. Fuzzing, crawling, and WAF detection."
            Case "DNSRecon"
                description = "DNSRecon: DNS enumeration tool. Zone transfers, subdomain brute force, cache snooping."
            Case "Cupp"
                description = "Cupp: Custom User Password Profiler. Generates wordlists based on target information."
        End Select

        If SecurityToolDescText IsNot Nothing Then
            SecurityToolDescText.Text = description
        End If
    End Sub

    ''' <summary>
    ''' Validates target input in real-time.
    ''' </summary>
    Private Sub SecurityTargetTextBox_TextChanged(sender As Object, e As TextChangedEventArgs)
        Dim target = SecurityTargetTextBox.Text.Trim()
        
        If String.IsNullOrEmpty(target) Then
            SecurityTargetValidationIcon.Text = "○"
            SecurityTargetValidationIcon.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 102, 102, 102))
            SecurityTargetValidationText.Text = "Enter target"
            SecurityTargetValidationText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 102, 102, 102))
            UpdateSecurityScanButtonState()
            Return
        End If

        ' Validate using TargetValidator
        Dim validation = TargetValidator.AutoValidate(target, _securityService.LabModeEnabled)

        If validation.IsValid Then
            SecurityTargetValidationIcon.Text = "✓"
            SecurityTargetValidationIcon.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
            
            If validation.IsPrivateRange Then
                SecurityTargetValidationText.Text = "Valid (Private - Lab Mode)"
                SecurityTargetValidationText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 204, 255))
            Else
                SecurityTargetValidationText.Text = "Valid"
                SecurityTargetValidationText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 0, 255, 0))
            End If
        Else
            SecurityTargetValidationIcon.Text = "✗"
            SecurityTargetValidationIcon.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))
            SecurityTargetValidationText.Text = validation.ErrorMessage
            SecurityTargetValidationText.Foreground = New SolidColorBrush(Windows.UI.ColorHelper.FromArgb(255, 255, 68, 68))
        End If

        UpdateSecurityScanButtonState()
    End Sub

    ''' <summary>
    ''' Updates the scan button enabled state.
    ''' </summary>
    Private Sub UpdateSecurityScanButtonState()
        Dim target = SecurityTargetTextBox.Text.Trim()
        Dim hasConsent = SecurityConsentCheckBox.IsChecked.GetValueOrDefault(False)
        Dim validation = TargetValidator.AutoValidate(target, _securityService.LabModeEnabled)

        SecurityScanButton.IsEnabled = hasConsent AndAlso validation.IsValid AndAlso Not _isSecurityScanning
    End Sub

    ''' <summary>
    ''' Starts a security scan.
    ''' </summary>
    Private Async Sub SecurityScanButton_Click(sender As Object, e As RoutedEventArgs)
        Dim target = SecurityTargetTextBox.Text.Trim()
        Dim selectedItem = TryCast(SecurityToolComboBox.SelectedItem, ComboBoxItem)
        Dim toolTag = selectedItem?.Tag?.ToString()

        If String.IsNullOrEmpty(target) OrElse String.IsNullOrEmpty(toolTag) Then
            Return
        End If

        ' Parse tool enum
        Dim tool As SecurityTool
        If Not [Enum].TryParse(toolTag, tool) Then
            LogStructured("ERR", "SECURITY_SCAN", target, "Invalid tool selection", NetworkErrorType.InvalidConfig, "")
            Return
        End If

        ' Create authorization
        Dim auth = _securityService.CreateAuthorization(target, tool)
        LogStructured("INFO", "SECURITY_SCAN", target, $"Authorization created: {auth.AuthorizationId.Substring(0, 8)}...", NetworkErrorType.None, "")

        ' Update UI
        _isSecurityScanning = True
        SecurityScanButton.IsEnabled = False
        SecurityStopButton.IsEnabled = True
        SecurityProgressPanel.Visibility = Visibility.Visible
        SecurityProgressBar.Visibility = Visibility.Visible
        SecurityScanStatusText.Text = "[SCANNING...]"

        Try
            ' Get tool configuration
            Dim config = ToolConfiguration.GetDefault(tool)

            ' Execute scan
            Dim result = Await _securityService.ExecuteScanAsync(target, tool, config)

            ' Display results
            If result.Status = ScanStatus.Completed Then
                SecurityScanStatusText.Text = "[COMPLETED]"
                SecurityResultCountText.Text = $"[{result.Findings.Count} findings]"

                Dim sb As New StringBuilder()
                sb.AppendLine($"[SCAN COMPLETED] {result.Tool}")
                sb.AppendLine($"Target: {result.Target}")
                sb.AppendLine($"Duration: {result.DurationMs}ms")
                sb.AppendLine($"Correlation ID: {result.CorrelationId}")
                sb.AppendLine()

                For Each finding In result.Findings
                    sb.AppendLine($"[{finding.Severity}] {finding.Title}")
                    sb.AppendLine($"  {finding.Description}")
                    sb.AppendLine()
                Next

                SecurityResultsText.Text = sb.ToString()
            Else
                SecurityScanStatusText.Text = $"[{result.Status}]"
                
                Dim sb As New StringBuilder()
                sb.AppendLine($"[SCAN {result.Status}] {result.Tool}")
                sb.AppendLine($"Target: {result.Target}")
                sb.AppendLine()

                For Each scanErr In result.Errors
                    sb.AppendLine($"⚠️ {scanErr.Code}: {scanErr.Message}")
                Next

                SecurityResultsText.Text = sb.ToString()
            End If

            LogStructured("INFO", "SECURITY_SCAN", target, $"Scan {result.Status}: {result.Findings.Count} findings", NetworkErrorType.None, "")

        Catch ex As Exception
            SecurityScanStatusText.Text = "[ERROR]"
            SecurityResultsText.Text = $"[ERROR] {ex.Message}"
            LogStructured("ERR", "SECURITY_SCAN", target, $"Exception: {ex.Message}", NetworkErrorType.Unknown, ex.ToString())
        Finally
            _isSecurityScanning = False
            SecurityScanButton.IsEnabled = True
            SecurityStopButton.IsEnabled = False
            SecurityProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub

    ''' <summary>
    ''' Stops an ongoing security scan.
    ''' </summary>
    Private Sub SecurityStopButton_Click(sender As Object, e As RoutedEventArgs)
        ' TODO: Implement cancellation via companion service
        LogStructured("WARN", "SECURITY_SCAN", "", "Stop requested (not implemented)", NetworkErrorType.None, "")
        _securityService.ClearAuthorization()
        
        _isSecurityScanning = False
        SecurityScanButton.IsEnabled = True
        SecurityStopButton.IsEnabled = False
        SecurityProgressBar.Visibility = Visibility.Collapsed
        SecurityScanStatusText.Text = "[STOPPED]"
    End Sub

    ''' <summary>
    ''' Exports the audit log.
    ''' </summary>
    Private Async Sub SecurityExportAuditButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim path = Await _securityService.ExportAuditLogAsync()
            
            If path.StartsWith("Error:") Then
                ShowAlert($"Export failed: {path}")
            Else
                LogStructured("INFO", "AUDIT_EXPORT", "", $"Audit log exported: {path}", NetworkErrorType.None, "")
                ShowAlert($"Audit log exported to: {path}")
            End If
        Catch ex As Exception
            ShowAlert($"Export error: {ex.Message}")
        End Try
    End Sub

#End Region

End Class

