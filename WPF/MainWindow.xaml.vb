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

Namespace RootcastleNetworkMonitor
    Class MainWindow

        Private _networkInterfaces As NetworkInterface()
        Private _selectedInterface As NetworkInterface
        Private _isMonitoring As Boolean = False
        Private _isCapturing As Boolean = False
        Private _monitoringCts As CancellationTokenSource
        Private _lastBytesSent As Long = 0
        Private _lastBytesReceived As Long = 0
        Private _totalBytesSent As Long = 0
        Private _totalBytesReceived As Long = 0
        Private _startTime As DateTime
        Private _uptimeTimer As Threading.Timer
        Private _nmapProcess As Process
        Private _packetCount As Long = 0

        Public Sub New()
            InitializeComponent()
            _startTime = DateTime.Now
            LoadNetworkInterfaces()
            Task.Run(AddressOf GetExternalIP)
            _uptimeTimer = New Threading.Timer(AddressOf UpdateUptime, Nothing, 1000, 1000)
            LogTerminal("[SYS] Rootcastle v6.0 WPF initialized")
            LogTerminal("[SYS] All features loaded")
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
                    _selectedInterface = _networkInterfaces(0)
                    UpdateInterfaceInfo()
                End If

                LogTerminal($"[NET] Found {_networkInterfaces.Length} interfaces")
            Catch ex As Exception
                LogTerminal($"[ERR] {ex.Message}")
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

        Private Sub InterfaceComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
            If InterfaceComboBox.SelectedIndex >= 0 AndAlso InterfaceComboBox.SelectedIndex < _networkInterfaces.Length Then
                _selectedInterface = _networkInterfaces(InterfaceComboBox.SelectedIndex)
                UpdateInterfaceInfo()
            End If
        End Sub

        Private Sub UpdateInterfaceInfo()
            If _selectedInterface Is Nothing Then Return

            InterfaceNameText.Text = $"Name: {_selectedInterface.Name}"
            InterfaceTypeText.Text = $"Type: {_selectedInterface.NetworkInterfaceType}"
            InterfaceSpeedText.Text = $"Speed: {_selectedInterface.Speed / 1000000} Mbps"
            MacAddressText.Text = $"MAC: {_selectedInterface.GetPhysicalAddress()}"

            Try
                Dim props = _selectedInterface.GetIPProperties()
                Dim ipv4 = props.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
                Dim gateway = props.GatewayAddresses.FirstOrDefault()

                IPv4Text.Text = $"IPv4: {If(ipv4?.Address?.ToString(), "-")}"
                SubnetText.Text = $"Subnet: {If(ipv4?.IPv4Mask?.ToString(), "-")}"
                GatewayFullText.Text = $"Gateway: {If(gateway?.Address?.ToString(), "-")}"
                GatewayText.Text = If(gateway?.Address?.ToString()?.Split("."c).LastOrDefault(), "-")
                DnsText.Text = $"DNS: {String.Join(", ", props.DnsAddresses.Take(2).Select(Function(d) d.ToString()))}"

                Dim stats = _selectedInterface.GetIPv4Statistics()
                _lastBytesSent = stats.BytesSent
                _lastBytesReceived = stats.BytesReceived
            Catch
            End Try
        End Sub

        Private Sub UpdateUptime(state As Object)
            Dispatcher.Invoke(Sub()
                Dim uptime = DateTime.Now - _startTime
                UptimeText.Text = $"{uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}"
            End Sub)
        End Sub

#Region "Monitoring"
        Private Sub StartButton_Click(sender As Object, e As RoutedEventArgs)
            If _isMonitoring Then
                StopMonitoring()
            Else
                StartMonitoring()
            End If
        End Sub

        Private Sub StartMonitoring()
            _isMonitoring = True
            _monitoringCts = New CancellationTokenSource()
            StartButton.Content = "⏹ STOP"
            StatusIndicator.Foreground = New SolidColorBrush(Colors.Lime)
            StatusText.Text = "[MONITORING]"
            LogTerminal($"[NET] Monitoring started on {_selectedInterface?.Name}")

            Task.Run(Async Function()
                While Not _monitoringCts.IsCancellationRequested
                    Await Task.Delay(1000)
                    Dispatcher.Invoke(Sub() UpdateStats())
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

        Private Sub UpdateStats()
            Try
                If _selectedInterface Is Nothing Then Return
                Dim stats = _selectedInterface.GetIPv4Statistics()
                Dim deltaSent = stats.BytesSent - _lastBytesSent
                Dim deltaRecv = stats.BytesReceived - _lastBytesReceived
                _lastBytesSent = stats.BytesSent
                _lastBytesReceived = stats.BytesReceived
                _totalBytesSent = stats.BytesSent
                _totalBytesReceived = stats.BytesReceived

                DownloadSpeedText.Text = $"{FormatBytes(deltaRecv)}/s"
                UploadSpeedText.Text = $"{FormatBytes(deltaSent)}/s"
                BytesPerSecText.Text = $"{FormatBytes(deltaSent + deltaRecv)}/s"

                _packetCount += 1
                PacketCountText.Text = _packetCount.ToString()
            Catch
            End Try
        End Sub
#End Region

#Region "Connection Capture"
        Private Sub CaptureButton_Click(sender As Object, e As RoutedEventArgs)
            If _isCapturing Then
                _isCapturing = False
                CaptureButton.Content = "● CAPTURE"
                LogTerminal("[PCAP] Capture stopped")
            Else
                _isCapturing = True
                CaptureButton.Content = "⏹ STOP"
                LogTerminal("[PCAP] Starting capture...")
                Task.Run(Async Function()
                    While _isCapturing
                        Await CaptureConnections()
                        Await Task.Delay(2000)
                    End While
                End Function)
            End If
        End Sub

        Private Async Function CaptureConnections() As Task
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
                    Dim conns = lines.Where(Function(l) l.Contains("ESTABLISHED") OrElse l.Contains("TIME_WAIT")).Take(30).ToList()

                    Dispatcher.Invoke(Sub()
                        ConnectionsListBox.Items.Clear()
                        For Each c In conns
                            ConnectionsListBox.Items.Add(c.Trim())
                        Next
                        ConnectionCountText.Text = conns.Count.ToString()
                    End Sub)
                End Using
            Catch
            End Try
        End Function
#End Region

#Region "NMAP Scanner"
        Private Sub NmapScanButton_Click(sender As Object, e As RoutedEventArgs)
            If Not ScanPermissionCheckBox.IsChecked.GetValueOrDefault(False) Then
                NmapOutputTextBox.Text = "[NMAP] ERROR: Check authorization box first!"
                Return
            End If

            Dim target = NmapTargetTextBox.Text.Trim()
            If String.IsNullOrEmpty(target) Then Return

            Dim scanArgs = GetNmapArgs()
            NmapOutputTextBox.Text = $"[NMAP] Scanning {target} with args: {scanArgs}{vbCrLf}"
            NmapStopButton.IsEnabled = True
            LogTerminal($"[NMAP] Executing: nmap {scanArgs} {target}")

            Task.Run(Async Function()
                Try
                    Dim psi As New ProcessStartInfo()
                    psi.FileName = "nmap"
                    psi.Arguments = $"{scanArgs} {target}"
                    psi.RedirectStandardOutput = True
                    psi.RedirectStandardError = True
                    psi.UseShellExecute = False
                    psi.CreateNoWindow = True

                    _nmapProcess = Process.Start(psi)
                    While Not _nmapProcess.StandardOutput.EndOfStream
                        Dim line = Await _nmapProcess.StandardOutput.ReadLineAsync()
                        Dispatcher.Invoke(Sub()
                            NmapOutputTextBox.AppendText(line + vbCrLf)
                            NmapOutputTextBox.ScrollToEnd()
                        End Sub)
                    End While
                    _nmapProcess.WaitForExit()
                    Dispatcher.Invoke(Sub()
                        NmapStopButton.IsEnabled = False
                        LogTerminal("[NMAP] Scan completed")
                    End Sub)
                Catch ex As Exception
                    Dispatcher.Invoke(Sub()
                        NmapOutputTextBox.AppendText($"{vbCrLf}[ERROR] {ex.Message}{vbCrLf}Make sure nmap is installed and in PATH")
                        NmapStopButton.IsEnabled = False
                    End Sub)
                End Try
            End Function)
        End Sub

        Private Function GetNmapArgs() As String
            Select Case NmapScanTypeCombo.SelectedIndex
                Case 0 : Return "-sT -T4"
                Case 1 : Return "-sT -p 1-65535"
                Case 2 : Return "-sS"
                Case 3 : Return "-sV"
                Case Else : Return "-sT"
            End Select
        End Function

        Private Sub NmapStopButton_Click(sender As Object, e As RoutedEventArgs)
            Try
                _nmapProcess?.Kill()
                NmapStopButton.IsEnabled = False
                LogTerminal("[NMAP] Scan cancelled")
            Catch
            End Try
        End Sub
#End Region

#Region "Packet Sender"
        Private Async Sub PingButton_Click(sender As Object, e As RoutedEventArgs)
            Dim host = TargetHostTextBox.Text.Trim()
            LogTerminal($"[PING] Pinging {host}...")
            Try
                Using ping As New Ping()
                    Dim reply = Await ping.SendPingAsync(host, 3000)
                    If reply.Status = IPStatus.Success Then
                        LogTerminal($"[PING] Reply: time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}")
                    Else
                        LogTerminal($"[PING] {reply.Status}")
                    End If
                End Using
            Catch ex As Exception
                LogTerminal($"[PING] Failed: {ex.Message}")
            End Try
        End Sub

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

#Region "AI"
        Private Sub AIAnalyzeButton_Click(sender As Object, e As RoutedEventArgs)
            Dim apiKey = ApiKeyBox.Password
            If String.IsNullOrEmpty(apiKey) Then
                AIAnalysisText.Text = "[SOFIA] Please enter your OpenRouter API key"
                Return
            End If
            Dim query = AIQueryTextBox.Text.Trim()
            SendAIQuery(apiKey, query)
        End Sub

        Private Sub AIQuickAction_Click(sender As Object, e As RoutedEventArgs)
            Dim apiKey = ApiKeyBox.Password
            If String.IsNullOrEmpty(apiKey) Then
                AIAnalysisText.Text = "[SOFIA] Please enter your OpenRouter API key"
                Return
            End If
            Dim btn = TryCast(sender, Button)
            Dim tag = btn?.Tag?.ToString()
            Dim query = ""
            Select Case tag
                Case "traffic" : query = "Analyze my current network traffic patterns"
                Case "security" : query = "Perform a security assessment of my network"
                Case "report" : query = "Generate a summary report of network status"
            End Select
            AIQueryTextBox.Text = query
            SendAIQuery(apiKey, query)
        End Sub

        Private Sub SendAIQuery(apiKey As String, query As String)
            AIAnalysisText.Text = "[SOFIA] Analyzing..."
            AIStatusText.Text = "Processing..."
            LogTerminal("[AI] Sending query...")

            Dim context = $"Interface: {_selectedInterface?.Name}, Down: {DownloadSpeedText.Text}, Up: {UploadSpeedText.Text}, Connections: {ConnectionCountText.Text}"

            Task.Run(Async Function()
                Try
                    Using client As New HttpClient()
                        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}")
                        client.DefaultRequestHeaders.Add("HTTP-Referer", "https://rootcastle.rei")

                        Dim modelItem = Nothing
                        Dim modelId = "meta-llama/llama-3.2-3b-instruct:free"
                        Dispatcher.Invoke(Sub()
                            modelItem = TryCast(AIModelComboBox.SelectedItem, ComboBoxItem)
                            If modelItem IsNot Nothing Then modelId = modelItem.Tag?.ToString()
                        End Sub)

                        Dim body As New JObject()
                        body("model") = modelId
                        Dim messages As New JArray()
                        messages.Add(New JObject() From {{"role", "system"}, {"content", "You are SOFIA, an expert network security AI assistant. Be concise and technical. Respond in Turkish."}})
                        messages.Add(New JObject() From {{"role", "user"}, {"content", $"Network: {context}{vbCrLf}Question: {query}"}})
                        body("messages") = messages
                        body("max_tokens") = 1500

                        Dim content As New StringContent(body.ToString(), Encoding.UTF8, "application/json")
                        Dim response = Await client.PostAsync("https://openrouter.ai/api/v1/chat/completions", content)
                        Dim txt = Await response.Content.ReadAsStringAsync()
                        Dim json = JObject.Parse(txt)
                        Dim result = json("choices")(0)("message")("content").ToString()

                        Dispatcher.Invoke(Sub()
                            AIAnalysisText.Text = result
                            AIStatusText.Text = "Ready"
                            LogTerminal("[AI] Response received")
                        End Sub)
                    End Using
                Catch ex As Exception
                    Dispatcher.Invoke(Sub()
                        AIAnalysisText.Text = $"[SOFIA ERROR] {ex.Message}"
                        AIStatusText.Text = "Error"
                    End Sub)
                End Try
            End Function)
        End Sub
#End Region

#Region "Utilities"
        Private Sub ClearTerminalButton_Click(sender As Object, e As RoutedEventArgs)
            TerminalOutput.Text = ""
        End Sub

        Private Sub LogTerminal(msg As String)
            Dispatcher.Invoke(Sub()
                TerminalOutput.Text += $"{vbCrLf}[{DateTime.Now:HH:mm:ss}] {msg}"
                TerminalScrollViewer.ScrollToEnd()
            End Sub)
        End Sub

        Private Function FormatBytes(bytes As Long) As String
            If bytes >= 1073741824 Then Return $"{bytes / 1073741824:F1} GB"
            If bytes >= 1048576 Then Return $"{bytes / 1048576:F1} MB"
            If bytes >= 1024 Then Return $"{bytes / 1024:F1} KB"
            Return $"{bytes} B"
        End Function

        Protected Overrides Sub OnClosed(e As EventArgs)
            _monitoringCts?.Cancel()
            _uptimeTimer?.Dispose()
            Try
                _nmapProcess?.Kill()
            Catch
            End Try
            MyBase.OnClosed(e)
        End Sub
#End Region

    End Class
End Namespace
