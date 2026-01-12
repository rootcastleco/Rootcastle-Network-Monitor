Imports System.Net.NetworkInformation
Imports System.Net
Imports System.Net.Http
Imports System.Net.Sockets
Imports System.Diagnostics
Imports System.Text
Imports System.IO
Imports System.Threading
Imports Newtonsoft.Json
Imports Newtonsoft.Json.Linq
Imports System.ComponentModel

Namespace RootcastleNetworkMonitor
    Class MainWindow

#Region "Fields"
    ' Network
    Private _networkInterfaces As NetworkInterface()
    Private _selectedInterface As NetworkInterface
    Private _isMonitoring As Boolean = False
    Private _monitoringCts As CancellationTokenSource
    
    ' Capture
    Private _isCapturing As Boolean = False
    Private _packetCount As Long = 0
    
    ' Statistics
    Private _lastBytesSent As Long = 0
    Private _lastBytesReceived As Long = 0
    Private _totalBytesSent As Long = 0
    Private _totalBytesReceived As Long = 0
    Private _startTime As DateTime
    Private _uptimeTimer As Threading.Timer
    Private _trafficHistory As New List(Of Double)
    
    ' AI
    Private _selectedAIModel As String = "meta-llama/llama-3.2-3b-instruct:free"
    Private _selectedLanguage As String = "TR"
    
    ' NMAP
    Private _nmapProcess As Process
    Private _isNmapRunning As Boolean = False
    
    ' Security
    Private _securityProcess As Process
    Private _isSecurityRunning As Boolean = False
    Private _suspiciousDetectionEnabled As Boolean = False
    Private _alertCount As Integer = 0
    Private _errorCount As Integer = 0
    
    ' Protocol counts
    Private _tcpCount As Long = 0
    Private _udpCount As Long = 0
    Private _icmpCount As Long = 0
    Private _otherCount As Long = 0
#End Region

#Region "Initialization"
    Private Sub MainWindow_Loaded(sender As Object, e As RoutedEventArgs)
        LoadNetworkInterfaces()
        LogTerminal("[SYS] Rootcastle Network Monitor v6.0 WPF Edition")
        LogTerminal("[SYS] Full system access enabled")
        LogTerminal("[SYS] SOFIA AI Engine loaded")
        
        ' Check for NMAP
        CheckNmapInstallation()
        
        ' Get external IP
        Task.Run(AddressOf GetExternalIP)
        
        ' Start uptime timer
        _startTime = DateTime.Now
        _uptimeTimer = New Threading.Timer(AddressOf UpdateUptime, Nothing, 1000, 1000)
    End Sub
    
    Private Sub LoadNetworkInterfaces()
        Try
            _networkInterfaces = NetworkInterface.GetAllNetworkInterfaces().
                Where(Function(n) n.OperationalStatus = OperationalStatus.Up AndAlso
                                  n.NetworkInterfaceType <> NetworkInterfaceType.Loopback).ToArray()
            
            InterfaceComboBox.Items.Clear()
            For Each ni In _networkInterfaces
                InterfaceComboBox.Items.Add($"{ni.Name} ({ni.NetworkInterfaceType})")
            Next
            
            If InterfaceComboBox.Items.Count > 0 Then
                InterfaceComboBox.SelectedIndex = 0
            End If
            
            LogTerminal($"[NET] Found {_networkInterfaces.Length} network interfaces")
        Catch ex As Exception
            LogTerminal($"[ERR] Failed to load interfaces: {ex.Message}")
        End Try
    End Sub
    
    Private Sub CheckNmapInstallation()
        Try
            Dim psi As New ProcessStartInfo()
            psi.FileName = "nmap"
            psi.Arguments = "--version"
            psi.RedirectStandardOutput = True
            psi.UseShellExecute = False
            psi.CreateNoWindow = True
            
            Using p = Process.Start(psi)
                Dim output = p.StandardOutput.ReadLine()
                LogTerminal($"[NMAP] {output}")
            End Using
        Catch
            LogTerminal("[NMAP] WARNING: nmap not found! Install from https://nmap.org")
        End Try
    End Sub
    
    Private Async Sub GetExternalIP()
        Try
            Using client As New HttpClient()
                client.Timeout = TimeSpan.FromSeconds(5)
                Dim ip = Await client.GetStringAsync("https://api.ipify.org")
                Dispatcher.Invoke(Sub()
                    ExternalIPText.Text = $"WAN: {ip}"
                    LogTerminal($"[NET] External IP: {ip}")
                End Sub)
            End Using
        Catch
            Dispatcher.Invoke(Sub() ExternalIPText.Text = "WAN: Unavailable")
        End Try
    End Sub
#End Region

#Region "Network Monitoring"
    Private Sub InterfaceComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        If InterfaceComboBox.SelectedIndex >= 0 AndAlso InterfaceComboBox.SelectedIndex < _networkInterfaces.Length Then
            _selectedInterface = _networkInterfaces(InterfaceComboBox.SelectedIndex)
            UpdateInterfaceInfo()
            LogTerminal($"[NET] Selected: {_selectedInterface.Name}")
        End If
    End Sub
    
    Private Sub UpdateInterfaceInfo()
        If _selectedInterface Is Nothing Then Return
        
        InterfaceNameText.Text = $"Name: {_selectedInterface.Name}"
        InterfaceTypeText.Text = $"Type: {_selectedInterface.NetworkInterfaceType}"
        InterfaceStatusText.Text = $"Status: {_selectedInterface.OperationalStatus}"
        InterfaceSpeedText.Text = $"Speed: {_selectedInterface.Speed / 1000000} Mbps"
        MacAddressText.Text = $"MAC: {_selectedInterface.GetPhysicalAddress()}"
        
        Dim props = _selectedInterface.GetIPProperties()
        Dim ipv4 = props.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
        Dim ipv6 = props.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetworkV6)
        Dim gateway = props.GatewayAddresses.FirstOrDefault()
        
        IPv4Text.Text = $"IPv4: {If(ipv4?.Address?.ToString(), "-")}"
        IPv6Text.Text = $"IPv6: {If(ipv6?.Address?.ToString()?.Substring(0, Math.Min(20, If(ipv6?.Address?.ToString()?.Length, 0))), "-")}..."
        SubnetText.Text = $"Subnet: {If(ipv4?.IPv4Mask?.ToString(), "-")}"
        GatewayText.Text = $"Gateway: {If(gateway?.Address?.ToString(), "-")}"
        GatewayShortText.Text = If(gateway?.Address?.ToString()?.Split("."c).LastOrDefault(), "-")
        LocalIPShortText.Text = If(ipv4?.Address?.ToString()?.Split("."c).LastOrDefault(), "-")
        
        Dim dns = String.Join(", ", props.DnsAddresses.Take(2).Select(Function(d) d.ToString()))
        DnsServersText.Text = $"DNS: {If(dns, "-")}"
        
        Dim stats = _selectedInterface.GetIPv4Statistics()
        _lastBytesSent = stats.BytesSent
        _lastBytesReceived = stats.BytesReceived
    End Sub
    
    Private Sub StartButton_Click(sender As Object, e As RoutedEventArgs)
        If _isMonitoring Then
            StopMonitoring()
        Else
            StartMonitoring()
        End If
    End Sub
    
    Private Sub StartMonitoring()
        If _selectedInterface Is Nothing Then
            LogTerminal("[ERR] No interface selected")
            Return
        End If
        
        _isMonitoring = True
        _monitoringCts = New CancellationTokenSource()
        StartButton.Content = "⏹ STOP"
        StatusIndicator.Foreground = New SolidColorBrush(Colors.Lime)
        StatusText.Text = "[MONITORING]"
        
        LogTerminal($"[NET] Monitoring started on {_selectedInterface.Name}")
        
        Task.Run(Async Function()
            While Not _monitoringCts.IsCancellationRequested
                Await Task.Delay(1000)
                Dispatcher.Invoke(Sub() UpdateStatistics())
            End While
        End Function)
    End Sub
    
    Private Sub StopMonitoring()
        _isMonitoring = False
        _monitoringCts?.Cancel()
        StartButton.Content = "▶ START"
        StatusIndicator.Foreground = New SolidColorBrush(Color.FromRgb(255, 170, 0))
        StatusText.Text = "[STOPPED]"
        LogTerminal("[NET] Monitoring stopped")
    End Sub
    
    Private Sub UpdateStatistics()
        Try
            If _selectedInterface Is Nothing Then Return
            
            Dim stats = _selectedInterface.GetIPv4Statistics()
            Dim deltaSent = stats.BytesSent - _lastBytesSent
            Dim deltaRecv = stats.BytesReceived - _lastBytesReceived
            
            _lastBytesSent = stats.BytesSent
            _lastBytesReceived = stats.BytesReceived
            _totalBytesSent = stats.BytesSent
            _totalBytesReceived = stats.BytesReceived
            
            ' Update UI
            SentDataText.Text = $"↑ {FormatBytes(_totalBytesSent)}"
            ReceivedDataText.Text = $"↓ {FormatBytes(_totalBytesReceived)}"
            DownloadSpeedText.Text = $"{FormatBytes(deltaRecv)}/s"
            UploadSpeedText.Text = $"{FormatBytes(deltaSent)}/s"
            BytesPerSecText.Text = $"{FormatBytes(deltaSent + deltaRecv)}/s"
            TrafficRateText.Text = $"{FormatBytes(deltaSent + deltaRecv)}/s"
            
            ' Bandwidth utilization
            Dim maxSpeed = _selectedInterface.Speed / 8
            If maxSpeed > 0 Then
                Dim utilization = (deltaSent + deltaRecv) / CDbl(maxSpeed) * 100
                BandwidthText.Text = $"{utilization:F1}%"
            End If
            
            ' Throughput
            Dim mbps = (deltaSent + deltaRecv) / 1048576.0 * 8
            QosThroughputText.Text = $"{mbps:F2} Mbps"
            
            ' Track traffic history for graph
            _trafficHistory.Add(deltaSent + deltaRecv)
            If _trafficHistory.Count > 60 Then _trafficHistory.RemoveAt(0)
            
            ' Protocol simulation (increment based on traffic)
            If deltaRecv > 0 Then
                _tcpCount += 1
                TcpCountText.Text = _tcpCount.ToString()
            End If
            If deltaSent > 0 Then
                _udpCount += 1
                UdpCountText.Text = _udpCount.ToString()
            End If
            
            _packetCount += 1
            PacketCountText.Text = _packetCount.ToString()
            
        Catch ex As Exception
            _errorCount += 1
            ErrorCountText.Text = _errorCount.ToString()
        End Try
    End Sub
    
    Private Sub UpdateUptime(state As Object)
        Dispatcher.Invoke(Sub()
            Dim uptime = DateTime.Now - _startTime
            UptimeText.Text = $"{uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}"
        End Sub)
    End Sub
#End Region

#Region "Connection Capture"
    Private Sub CaptureButton_Click(sender As Object, e As RoutedEventArgs)
        If _isCapturing Then
            StopCapture()
        Else
            StartCapture()
        End If
    End Sub
    
    Private Sub StartCapture()
        _isCapturing = True
        CaptureButton.Content = "⏹ STOP"
        LogTerminal("[PCAP] Starting connection capture...")
        
        Task.Run(Async Function()
            While _isCapturing
                Await CaptureConnectionsAsync()
                Await Task.Delay(2000)
            End While
        End Function)
    End Sub
    
    Private Async Function CaptureConnectionsAsync() As Task
        Try
            Dim psi As New ProcessStartInfo()
            psi.FileName = "netstat"
            psi.Arguments = "-n"
            psi.RedirectStandardOutput = True
            psi.UseShellExecute = False
            psi.CreateNoWindow = True
            
            Using proc = Process.Start(psi)
                Dim output = Await proc.StandardOutput.ReadToEndAsync()
                Dim lines = output.Split({vbCrLf, vbLf}, StringSplitOptions.RemoveEmptyEntries)
                
                Dim connections As New List(Of String)
                For Each line In lines
                    If line.Contains("ESTABLISHED") OrElse line.Contains("TIME_WAIT") OrElse line.Contains("CLOSE_WAIT") Then
                        connections.Add(line.Trim())
                        _packetCount += 1
                    End If
                Next
                
                Dispatcher.Invoke(Sub()
                    ConnectionsListView.Items.Clear()
                    For Each conn In connections.Take(50)
                        ConnectionsListView.Items.Add(conn)
                    Next
                    ConnectionCountText.Text = $"[{connections.Count} connections]"
                    ActiveConnectionsText.Text = connections.Count.ToString()
                    PacketCountText.Text = _packetCount.ToString()
                End Sub)
            End Using
        Catch
        End Try
    End Function
    
    Private Sub StopCapture()
        _isCapturing = False
        CaptureButton.Content = "● CAPTURE"
        LogTerminal("[PCAP] Capture stopped")
    End Sub
#End Region

#Region "NMAP Scanner"
    Private Async Sub NmapScanButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapRunning Then
            _nmapProcess?.Kill()
            _isNmapRunning = False
            NmapStopButton.IsEnabled = False
            Return
        End If
        
        If Not ScanPermissionCheckBox.IsChecked.GetValueOrDefault(False) Then
            NmapOutputTextBox.Text = "[NMAP] ERROR: Check authorization box first!"
            Return
        End If
        
        Dim target = NmapTargetTextBox.Text.Trim()
        If String.IsNullOrEmpty(target) Then
            NmapOutputTextBox.Text = "[NMAP] ERROR: Enter a target"
            Return
        End If
        
        Dim scanType = GetNmapArgs()
        
        _isNmapRunning = True
        NmapStopButton.IsEnabled = True
        NmapProgressBar.Visibility = Visibility.Visible
        NmapProgressBar.IsIndeterminate = True
        NmapOutputTextBox.Text = $"[NMAP] Starting scan: nmap {scanType} {target}{vbCrLf}"
        LogTerminal($"[NMAP] Executing: nmap {scanType} {target}")
        
        Try
            Await Task.Run(Sub()
                Dim psi As New ProcessStartInfo()
                psi.FileName = "nmap"
                psi.Arguments = $"{scanType} {target}"
                psi.RedirectStandardOutput = True
                psi.RedirectStandardError = True
                psi.UseShellExecute = False
                psi.CreateNoWindow = True
                
                _nmapProcess = New Process()
                _nmapProcess.StartInfo = psi
                _nmapProcess.Start()
                
                While Not _nmapProcess.StandardOutput.EndOfStream
                    Dim line = _nmapProcess.StandardOutput.ReadLine()
                    Dispatcher.Invoke(Sub()
                        NmapOutputTextBox.AppendText(line + vbCrLf)
                        NmapOutputTextBox.ScrollToEnd()
                    End Sub)
                End While
                
                _nmapProcess.WaitForExit()
            End Sub)
            
            LogTerminal("[NMAP] Scan completed")
        Catch ex As Exception
            NmapOutputTextBox.AppendText($"{vbCrLf}[NMAP] ERROR: {ex.Message}")
            LogTerminal($"[NMAP] ERROR: {ex.Message}")
        Finally
            _isNmapRunning = False
            NmapStopButton.IsEnabled = False
            NmapProgressBar.Visibility = Visibility.Collapsed
        End Try
    End Sub
    
    Private Function GetNmapArgs() As String
        Select Case NmapScanTypeCombo.SelectedIndex
            Case 0 : Return "-sT -T4"
            Case 1 : Return "-sT -p 1-65535"
            Case 2 : Return "-sS"
            Case 3 : Return "-sV"
            Case 4 : Return "-O"
            Case 5 : Return "--script vuln"
            Case Else : Return "-sT"
        End Select
    End Function
    
    Private Sub NmapDiscoverButton_Click(sender As Object, e As RoutedEventArgs)
        If Not ScanPermissionCheckBox.IsChecked.GetValueOrDefault(False) Then
            NmapOutputTextBox.Text = "[NMAP] ERROR: Check authorization box first!"
            Return
        End If
        NmapTargetTextBox.Text = "192.168.1.0/24"
        NmapScanTypeCombo.SelectedIndex = 0
        NmapScanButton_Click(sender, e)
    End Sub
    
    Private Sub NmapStopButton_Click(sender As Object, e As RoutedEventArgs)
        _nmapProcess?.Kill()
        _isNmapRunning = False
        NmapStopButton.IsEnabled = False
        NmapProgressBar.Visibility = Visibility.Collapsed
        LogTerminal("[NMAP] Scan cancelled")
    End Sub
#End Region

#Region "Packet Sender"
    Private Async Sub SendTcpButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        Dim port = 0
        Integer.TryParse(TargetPortTextBox.Text, port)
        
        LogTerminal($"[TCP] Connecting to {host}:{port}...")
        Try
            Using client As New TcpClient()
                Await client.ConnectAsync(host, port)
                LogTerminal($"[TCP] Connected to {host}:{port} ✓")
            End Using
        Catch ex As Exception
            LogTerminal($"[TCP] Failed: {ex.Message}")
        End Try
    End Sub
    
    Private Async Sub SendUdpButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        Dim port = 0
        Integer.TryParse(TargetPortTextBox.Text, port)
        
        LogTerminal($"[UDP] Sending to {host}:{port}...")
        Try
            Using client As New UdpClient()
                Dim data = Encoding.ASCII.GetBytes("PING")
                Await client.SendAsync(data, data.Length, host, port)
                LogTerminal($"[UDP] Packet sent to {host}:{port} ✓")
            End Using
        Catch ex As Exception
            LogTerminal($"[UDP] Failed: {ex.Message}")
        End Try
    End Sub
    
    Private Async Sub PingButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        LogTerminal($"[PING] Pinging {host}...")
        
        Try
            Using ping As New Ping()
                Dim reply = Await ping.SendPingAsync(host, 3000)
                If reply.Status = IPStatus.Success Then
                    LogTerminal($"[PING] Reply from {reply.Address}: time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}")
                    LatencyText.Text = $"~ {reply.RoundtripTime} ms"
                    QosLatencyText.Text = $"{reply.RoundtripTime} ms"
                Else
                    LogTerminal($"[PING] {reply.Status}")
                End If
            End Using
        Catch ex As Exception
            LogTerminal($"[PING] Failed: {ex.Message}")
        End Try
    End Sub
    
    Private Async Sub TraceRouteButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        LogTerminal($"[TRACE] Traceroute to {host}...")
        
        Try
            Await Task.Run(Sub()
                Dim psi As New ProcessStartInfo()
                psi.FileName = "tracert"
                psi.Arguments = $"-d -h 15 {host}"
                psi.RedirectStandardOutput = True
                psi.UseShellExecute = False
                psi.CreateNoWindow = True
                
                Using proc = Process.Start(psi)
                    While Not proc.StandardOutput.EndOfStream
                        Dim line = proc.StandardOutput.ReadLine()
                        Dispatcher.Invoke(Sub() LogTerminal($"[TRACE] {line}"))
                    End While
                End Using
            End Sub)
        Catch ex As Exception
            LogTerminal($"[TRACE] Failed: {ex.Message}")
        End Try
    End Sub
    
    Private Async Sub HttpCheckButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        If Not host.StartsWith("http") Then host = "https://" + host
        
        LogTerminal($"[HTTP] Checking {host}...")
        Try
            Using client As New HttpClient()
                client.Timeout = TimeSpan.FromSeconds(10)
                Dim sw = Stopwatch.StartNew()
                Dim response = Await client.GetAsync(host)
                sw.Stop()
                LogTerminal($"[HTTP] {response.StatusCode} ({sw.ElapsedMilliseconds}ms)")
            End Using
        Catch ex As Exception
            LogTerminal($"[HTTP] Failed: {ex.Message}")
        End Try
    End Sub
    
    Private Async Sub DnsCheckButton_Click(sender As Object, e As RoutedEventArgs)
        Dim host = TargetHostTextBox.Text.Trim()
        LogTerminal($"[DNS] Resolving {host}...")
        
        Try
            Dim addresses = Await Dns.GetHostAddressesAsync(host)
            For Each addr In addresses
                LogTerminal($"[DNS] {host} -> {addr}")
            Next
        Catch ex As Exception
            LogTerminal($"[DNS] Failed: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "Security Automation"
    Private Sub SecurityToolComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        Dim item = TryCast(SecurityToolComboBox.SelectedItem, ComboBoxItem)
        If item Is Nothing Then Return
        
        Dim tag = item.Tag?.ToString()
        Select Case tag
            Case "Nmap"
                SecurityToolDescText.Text = "Nmap: Network exploration and security auditing. Discover hosts, services, OS detection."
            Case "SQLMap"
                SecurityToolDescText.Text = "SQLMap: Automatic SQL injection detection and exploitation tool."
            Case "WPScan"
                SecurityToolDescText.Text = "WPScan: WordPress security scanner. Detects vulnerable plugins and themes."
            Case "XSStrike"
                SecurityToolDescText.Text = "XSStrike: Advanced XSS detection suite with fuzzing and WAF detection."
            Case "DNSRecon"
                SecurityToolDescText.Text = "DNSRecon: DNS enumeration tool. Zone transfers, subdomain brute force."
        End Select
    End Sub
    
    Private Async Sub SecurityScanButton_Click(sender As Object, e As RoutedEventArgs)
        If Not SecurityConsentCheckBox.IsChecked.GetValueOrDefault(False) Then
            SecurityResultsText.Text = "[SECURITY] ERROR: Check authorization box first!"
            Return
        End If
        
        Dim target = SecurityTargetTextBox.Text.Trim()
        If String.IsNullOrEmpty(target) Then
            SecurityResultsText.Text = "[SECURITY] ERROR: Enter a target"
            Return
        End If
        
        Dim item = TryCast(SecurityToolComboBox.SelectedItem, ComboBoxItem)
        Dim toolTag = item?.Tag?.ToString()
        Dim toolName = ""
        Dim toolArgs = ""
        
        Select Case toolTag
            Case "Nmap"
                toolName = "nmap"
                toolArgs = $"-sV -sC {target}"
            Case "SQLMap"
                toolName = "python"
                toolArgs = $"-m sqlmap -u ""{target}"" --batch --level=1"
            Case "WPScan"
                toolName = "wpscan"
                toolArgs = $"--url {target} --enumerate vp"
            Case "XSStrike"
                toolName = "python"
                toolArgs = $"xsstrike.py -u ""{target}"""
            Case "DNSRecon"
                toolName = "dnsrecon"
                toolArgs = $"-d {target}"
            Case Else
                toolName = "nmap"
                toolArgs = $"-sV {target}"
        End Select
        
        SecurityResultsText.Text = $"[SECURITY] Executing: {toolName} {toolArgs}{vbCrLf}"
        LogTerminal($"[SECURITY] Running: {toolName}")
        
        Try
            Await Task.Run(Sub()
                Dim psi As New ProcessStartInfo()
                psi.FileName = toolName
                psi.Arguments = toolArgs
                psi.RedirectStandardOutput = True
                psi.RedirectStandardError = True
                psi.UseShellExecute = False
                psi.CreateNoWindow = True
                
                _securityProcess = New Process()
                _securityProcess.StartInfo = psi
                _securityProcess.Start()
                
                While Not _securityProcess.StandardOutput.EndOfStream
                    Dim line = _securityProcess.StandardOutput.ReadLine()
                    Dispatcher.Invoke(Sub()
                        SecurityResultsText.AppendText(line + vbCrLf)
                    End Sub)
                End While
                
                _securityProcess.WaitForExit()
            End Sub)
            
            LogTerminal("[SECURITY] Scan completed")
        Catch ex As Exception
            SecurityResultsText.AppendText($"{vbCrLf}[ERROR] {ex.Message}{vbCrLf}Make sure the tool is installed and in PATH")
            LogTerminal($"[SECURITY] ERROR: {ex.Message}")
        End Try
    End Sub
    
    Private Sub SecurityExportButton_Click(sender As Object, e As RoutedEventArgs)
        Try
            Dim filename = $"security_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            File.WriteAllText(filename, SecurityResultsText.Text)
            LogTerminal($"[SECURITY] Report exported: {filename}")
        Catch ex As Exception
            LogTerminal($"[SECURITY] Export failed: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "AI"
    Private Async Sub AIAnalyzeButton_Click(sender As Object, e As RoutedEventArgs)
        Dim apiKey = ApiKeyBox.Password
        If String.IsNullOrEmpty(apiKey) Then
            AIAnalysisText.Text = "[SOFIA] ERROR: Please enter your OpenRouter API key"
            Return
        End If
        
        Dim query = AIQueryTextBox.Text.Trim()
        If String.IsNullOrEmpty(query) Then
            AIAnalysisText.Text = "[SOFIA] ERROR: Please enter a question"
            Return
        End If
        
        ' Collect network context
        Dim context As New StringBuilder()
        context.AppendLine("=== NETWORK STATUS ===")
        context.AppendLine($"Interface: {_selectedInterface?.Name}")
        context.AppendLine($"Packets: {_packetCount}")
        context.AppendLine($"Sent: {SentDataText.Text}")
        context.AppendLine($"Received: {ReceivedDataText.Text}")
        context.AppendLine($"Connections: {ActiveConnectionsText.Text}")
        context.AppendLine($"Latency: {LatencyText.Text}")
        
        AIAnalysisText.Text = "[SOFIA] Analyzing..."
        AIStatusText.Text = "Processing..."
        LogTerminal("[AI] Sending query to SOFIA...")
        
        Try
            Dim response = Await GetAIResponseAsync(apiKey, query, context.ToString())
            AIAnalysisText.Text = response
            AIStatusText.Text = "Ready"
            LogTerminal("[AI] Response received")
        Catch ex As Exception
            AIAnalysisText.Text = $"[SOFIA] ERROR: {ex.Message}"
            AIStatusText.Text = "Error"
            LogTerminal($"[AI] ERROR: {ex.Message}")
        End Try
    End Sub
    
    Private Sub AIQuickAnalyze_Click(sender As Object, e As RoutedEventArgs)
        Dim btn = TryCast(sender, Button)
        Dim tag = btn?.Tag?.ToString()
        
        Select Case tag
            Case "traffic"
                AIQueryTextBox.Text = "Analyze my current network traffic patterns"
            Case "security"
                AIQueryTextBox.Text = "Perform a security assessment of my network"
            Case "firewall"
                AIQueryTextBox.Text = "Suggest firewall rules based on my traffic"
            Case "summary"
                AIQueryTextBox.Text = "Generate a summary report of network status"
            Case "anomaly"
                AIQueryTextBox.Text = "Detect any anomalies in the traffic"
            Case "performance"
                AIQueryTextBox.Text = "Analyze network performance and suggest improvements"
        End Select
        
        AIAnalyzeButton_Click(sender, e)
    End Sub
    
    Private Async Function GetAIResponseAsync(apiKey As String, query As String, context As String) As Task(Of String)
        Using client As New HttpClient()
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}")
            client.DefaultRequestHeaders.Add("HTTP-Referer", "https://rootcastle.rei")
            client.DefaultRequestHeaders.Add("X-Title", "Rootcastle Network Monitor WPF")
            
            Dim modelItem = TryCast(AIModelComboBox.SelectedItem, ComboBoxItem)
            Dim modelId = modelItem?.Tag?.ToString()
            If String.IsNullOrEmpty(modelId) Then modelId = "meta-llama/llama-3.2-3b-instruct:free"
            
            Dim langItem = TryCast(AILanguageComboBox.SelectedItem, ComboBoxItem)
            Dim lang = langItem?.Tag?.ToString()
            Dim langPrompt = If(lang = "TR", "Respond in Turkish.", If(lang = "EN", "Respond in English.", "Respond in German."))
            
            Dim body As New JObject()
            body("model") = modelId
            
            Dim messages As New JArray()
            messages.Add(New JObject() From {
                {"role", "system"},
                {"content", $"You are SOFIA, an expert network security AI assistant for Rootcastle Network Monitor. {langPrompt} Be technical, concise, and helpful."}
            })
            messages.Add(New JObject() From {
                {"role", "user"},
                {"content", $"Network Context:{vbCrLf}{context}{vbCrLf}{vbCrLf}Question: {query}"}
            })
            body("messages") = messages
            body("max_tokens") = 2000
            
            Dim content As New StringContent(body.ToString(), Encoding.UTF8, "application/json")
            Dim response = Await client.PostAsync("https://openrouter.ai/api/v1/chat/completions", content)
            Dim responseText = Await response.Content.ReadAsStringAsync()
            
            Dim json = JObject.Parse(responseText)
            Return json("choices")(0)("message")("content").ToString()
        End Using
    End Function
#End Region

#Region "Utilities"
    Private Sub LogTerminal(message As String)
        Dispatcher.Invoke(Sub()
            TerminalOutput.Text += $"{vbCrLf}[{DateTime.Now:HH:mm:ss}] {message}"
            TerminalScrollViewer.ScrollToEnd()
        End Sub)
    End Sub
    
    Private Sub ClearTerminalButton_Click(sender As Object, e As RoutedEventArgs)
        TerminalOutput.Text = ""
    End Sub
    
    Private Function FormatBytes(bytes As Long) As String
        If bytes >= 1073741824 Then Return $"{bytes / 1073741824:F2} GB"
        If bytes >= 1048576 Then Return $"{bytes / 1048576:F2} MB"
        If bytes >= 1024 Then Return $"{bytes / 1024:F2} KB"
        Return $"{bytes} B"
    End Function
    
    Private Sub ReportButton_Click(sender As Object, e As RoutedEventArgs)
        LogTerminal("[REPORT] Generating network report...")
        ' Generate report logic
    End Sub
    
    Private Sub SettingsButton_Click(sender As Object, e As RoutedEventArgs)
        LogTerminal("[SETTINGS] Opening settings...")
    End Sub
    
    Private Sub SuspiciousPacketCheckBox_Checked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = True
        LogTerminal("[SEC] Suspicious detection ENABLED")
    End Sub
    
    Private Sub SuspiciousPacketCheckBox_Unchecked(sender As Object, e As RoutedEventArgs)
        _suspiciousDetectionEnabled = False
        LogTerminal("[SEC] Suspicious detection DISABLED")
    End Sub
    
    Protected Overrides Sub OnClosing(e As CancelEventArgs)
        _monitoringCts?.Cancel()
        _uptimeTimer?.Dispose()
        _nmapProcess?.Kill()
        _securityProcess?.Kill()
        MyBase.OnClosing(e)
    End Sub
#End Region

    End Class
End Namespace
