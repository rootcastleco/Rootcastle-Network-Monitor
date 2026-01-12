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

        Public Sub New()
            InitializeComponent()
            LoadNetworkInterfaces()
            LogTerminal("[SYS] Rootcastle v6.0 WPF initialized")
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

        Private Sub UpdateInterfaceInfo()
            If _selectedInterface Is Nothing Then Return

            InterfaceNameText.Text = $"Name: {_selectedInterface.Name}"
            InterfaceTypeText.Text = $"Type: {_selectedInterface.NetworkInterfaceType}"
            InterfaceStatusText.Text = $"Status: {_selectedInterface.OperationalStatus}"
            InterfaceSpeedText.Text = $"Speed: {_selectedInterface.Speed / 1000000} Mbps"
            MacAddressText.Text = $"MAC: {_selectedInterface.GetPhysicalAddress()}"

            Try
                Dim props = _selectedInterface.GetIPProperties()
                Dim ipv4 = props.UnicastAddresses.FirstOrDefault(Function(a) a.Address.AddressFamily = AddressFamily.InterNetwork)
                Dim gateway = props.GatewayAddresses.FirstOrDefault()

                IPv4Text.Text = $"IPv4: {If(ipv4?.Address?.ToString(), "-")}"
                IPv6Text.Text = "IPv6: -"
                SubnetText.Text = $"Subnet: {If(ipv4?.IPv4Mask?.ToString(), "-")}"
                GatewayFullText.Text = $"Gateway: {If(gateway?.Address?.ToString(), "-")}"
                GatewayText.Text = If(gateway?.Address?.ToString()?.Split("."c).LastOrDefault(), "-")

                Dim stats = _selectedInterface.GetIPv4Statistics()
                _lastBytesSent = stats.BytesSent
                _lastBytesReceived = stats.BytesReceived
            Catch
            End Try
        End Sub

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
            LogTerminal($"[NET] Monitoring started")

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

                DownloadSpeedText.Text = $"{FormatBytes(deltaRecv)}/s"
                UploadSpeedText.Text = $"{FormatBytes(deltaSent)}/s"
            Catch
            End Try
        End Sub

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
                    Dim conns = lines.Where(Function(l) l.Contains("ESTABLISHED")).Take(20).ToList()

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

        Private Sub NmapScanButton_Click(sender As Object, e As RoutedEventArgs)
            Dim target = NmapTargetTextBox.Text.Trim()
            If String.IsNullOrEmpty(target) Then Return

            LogTerminal($"[NMAP] Scanning {target}...")
            NmapOutputTextBox.Text = $"[NMAP] Scanning {target}...{vbCrLf}"

            Task.Run(Async Function()
                Try
                    Dim psi As New ProcessStartInfo()
                    psi.FileName = "nmap"
                    psi.Arguments = $"-sT -T4 {target}"
                    psi.RedirectStandardOutput = True
                    psi.RedirectStandardError = True
                    psi.UseShellExecute = False
                    psi.CreateNoWindow = True

                    Using proc = Process.Start(psi)
                        While Not proc.StandardOutput.EndOfStream
                            Dim line = Await proc.StandardOutput.ReadLineAsync()
                            Dispatcher.Invoke(Sub()
                                NmapOutputTextBox.AppendText(line + vbCrLf)
                            End Sub)
                        End While
                    End Using
                Catch ex As Exception
                    Dispatcher.Invoke(Sub()
                        NmapOutputTextBox.AppendText($"[ERROR] {ex.Message}{vbCrLf}")
                    End Sub)
                End Try
            End Function)
        End Sub

        Private Sub AIAnalyzeButton_Click(sender As Object, e As RoutedEventArgs)
            Dim apiKey = ApiKeyBox.Password
            If String.IsNullOrEmpty(apiKey) Then
                AIAnalysisText.Text = "[SOFIA] Please enter API key"
                Return
            End If

            Dim query = AIQueryTextBox.Text.Trim()
            AIAnalysisText.Text = "[SOFIA] Analyzing..."
            LogTerminal("[AI] Sending query...")

            Task.Run(Async Function()
                Try
                    Using client As New HttpClient()
                        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}")

                        Dim body As New JObject()
                        body("model") = "meta-llama/llama-3.2-3b-instruct:free"
                        Dim messages As New JArray()
                        messages.Add(New JObject() From {{"role", "system"}, {"content", "You are SOFIA, a network AI assistant."}})
                        messages.Add(New JObject() From {{"role", "user"}, {"content", query}})
                        body("messages") = messages

                        Dim content As New StringContent(body.ToString(), Encoding.UTF8, "application/json")
                        Dim response = Await client.PostAsync("https://openrouter.ai/api/v1/chat/completions", content)
                        Dim txt = Await response.Content.ReadAsStringAsync()
                        Dim json = JObject.Parse(txt)

                        Dispatcher.Invoke(Sub()
                            AIAnalysisText.Text = json("choices")(0)("message")("content").ToString()
                        End Sub)
                    End Using
                Catch ex As Exception
                    Dispatcher.Invoke(Sub()
                        AIAnalysisText.Text = $"[ERROR] {ex.Message}"
                    End Sub)
                End Try
            End Function)
        End Sub

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
            If bytes >= 1048576 Then Return $"{bytes / 1048576:F1} MB"
            If bytes >= 1024 Then Return $"{bytes / 1024:F1} KB"
            Return $"{bytes} B"
        End Function

    End Class
End Namespace
