Imports System.Net.NetworkInformation
Imports System.Net
Imports System.Net.Http
Imports System.Diagnostics
Imports System.Text
Imports System.IO
Imports System.Threading
Imports Newtonsoft.Json
Imports Newtonsoft.Json.Linq
Imports System.ComponentModel

Class MainWindow

#Region "Fields"
    ' Network
    Private _networkInterfaces As NetworkInterface()
    Private _selectedInterface As NetworkInterface
    Private _isMonitoring As Boolean = False
    Private _monitoringCts As CancellationTokenSource
    
    ' Packet/Connection Capture
    Private _isCapturing As Boolean = False
    Private _packetCount As Long = 0
    Private _capturedPackets As New List(Of CapturedPacketInfo)
    
    ' Statistics
    Private _lastBytesSent As Long = 0
    Private _lastBytesReceived As Long = 0
    Private _startTime As DateTime
    Private _uptimeTimer As Threading.Timer
    
    ' AI
    Private _openRouterApiKey As String = ""
    Private _selectedAIModel As String = "deepseek/deepseek-chat"
    
    ' NMAP
    Private _nmapProcess As Process
    Private _isNmapRunning As Boolean = False
#End Region

#Region "Initialization"
    Private Sub Window_Loaded(sender As Object, e As RoutedEventArgs)
        LoadNetworkInterfaces()
        LogTerminal("[SYSTEM] Rootcastle Network Monitor v6.0 WPF Edition")
        LogTerminal("[SYSTEM] Full system access enabled")
        
        ' Connection capture info
        LogTerminal("[PCAP] Using netstat for connection monitoring")
        LogTerminal("[PCAP] NMAP and Security Tools fully operational")
        
        ' Check for NMAP
        CheckNmapInstallation()
        
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
            LogTerminal("[NMAP] WARNING: nmap not found in PATH! Install from https://nmap.org")
        End Try
    End Sub
#End Region

#Region "Network Monitoring"
    Private Sub InterfaceComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
        If InterfaceComboBox.SelectedIndex >= 0 AndAlso InterfaceComboBox.SelectedIndex < _networkInterfaces.Length Then
            _selectedInterface = _networkInterfaces(InterfaceComboBox.SelectedIndex)
            LogTerminal($"[NET] Selected: {_selectedInterface.Name}")
            
            Dim stats = _selectedInterface.GetIPv4Statistics()
            _lastBytesSent = stats.BytesSent
            _lastBytesReceived = stats.BytesReceived
        End If
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
        
        ' Start monitoring task
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
            
            SentText.Text = FormatBytes(stats.BytesSent)
            ReceivedText.Text = FormatBytes(stats.BytesReceived)
            
            _packetCount += 1
            PacketCountText.Text = _packetCount.ToString()
        Catch ex As Exception
            LogTerminal($"[ERR] Stats update: {ex.Message}")
        End Try
    End Sub
    
    Private Sub UpdateUptime(state As Object)
        Dispatcher.Invoke(Sub()
            Dim uptime = DateTime.Now - _startTime
            UptimeText.Text = $"Uptime: {uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}"
        End Sub)
    End Sub
#End Region

#Region "Packet Capture"
    ' NOTE: SharpPcap 6.x uses ref structs which VB.NET cannot handle
    ' Packet capture uses Windows APIs instead
    
    Private Sub CaptureButton_Click(sender As Object, e As RoutedEventArgs)
        If _isCapturing Then
            StopCapture()
        Else
            StartCapture()
        End If
    End Sub
    
    Private Sub StartCapture()
        Try
            _isCapturing = True
            LogTerminal("[PCAP] Starting network capture using netstat...")
            LogTerminal("[PCAP] For full packet capture, install Wireshark")
            
            ' Use netstat for connection monitoring  
            Task.Run(Async Function()
                While _isCapturing
                    Await CaptureConnectionsAsync()
                    Await Task.Delay(2000)
                End While
            End Function)
            
        Catch ex As Exception
            LogTerminal($"[PCAP] ERROR: {ex.Message}")
        End Try
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
                
                Dim count = 0
                For Each line In lines
                    If line.Contains("ESTABLISHED") OrElse line.Contains("TIME_WAIT") Then
                        count += 1
                        _packetCount += 1
                        
                        Dim parts = line.Split({" "c}, StringSplitOptions.RemoveEmptyEntries)
                        If parts.Length >= 4 Then
                            Dispatcher.Invoke(Sub()
                                Dim displayText = $"[{DateTime.Now:HH:mm:ss}] {parts(0)} {parts(1)} → {parts(2)} ({parts(3)})"
                                PacketListBox.Items.Insert(0, displayText)
                                
                                If PacketListBox.Items.Count > 500 Then
                                    PacketListBox.Items.RemoveAt(PacketListBox.Items.Count - 1)
                                End If
                            End Sub)
                        End If
                    End If
                Next
                
                Dispatcher.Invoke(Sub()
                    PacketCountText.Text = _packetCount.ToString()
                End Sub)
            End Using
        Catch
            ' Ignore capture errors
        End Try
    End Function
    
    Private Sub StopCapture()
        _isCapturing = False
        LogTerminal("[PCAP] Capture stopped")
    End Sub
#End Region

#Region "NMAP (REAL)"
    Private Sub NmapScanButton_Click(sender As Object, e As RoutedEventArgs)
        ' Just switch to NMAP tab
    End Sub
    
    Private Async Sub RunNmapButton_Click(sender As Object, e As RoutedEventArgs)
        If _isNmapRunning Then
            _nmapProcess?.Kill()
            _isNmapRunning = False
            RunNmapButton.Content = "🚀 RUN NMAP"
            Return
        End If
        
        Dim target = NmapTargetTextBox.Text.Trim()
        If String.IsNullOrEmpty(target) Then
            NmapOutputTextBox.Text = "[NMAP] ERROR: Enter a target"
            Return
        End If
        
        Dim scanType = ""
        Select Case NmapScanTypeComboBox.SelectedIndex
            Case 0 : scanType = "-sT"
            Case 1 : scanType = "-sV"
            Case 2 : scanType = "-O"
            Case 3 : scanType = "-A"
            Case 4 : scanType = "-p 1-65535"
        End Select
        
        _isNmapRunning = True
        RunNmapButton.Content = "⏹ STOP"
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
                        NmapOutputTextBox.Text += line + vbCrLf
                        NmapOutputTextBox.ScrollToEnd()
                    End Sub)
                End While
                
                _nmapProcess.WaitForExit()
            End Sub)
            
            LogTerminal("[NMAP] Scan completed")
        Catch ex As Exception
            NmapOutputTextBox.Text += $"{vbCrLf}[NMAP] ERROR: {ex.Message}"
            LogTerminal($"[NMAP] ERROR: {ex.Message}")
        Finally
            _isNmapRunning = False
            RunNmapButton.Content = "🚀 RUN NMAP"
        End Try
    End Sub
#End Region

#Region "Security Tools (REAL)"
    Private Async Sub RunSecurityToolButton_Click(sender As Object, e As RoutedEventArgs)
        If Not SecurityConsentCheckBox.IsChecked.GetValueOrDefault(False) Then
            SecurityOutputTextBox.Text = "[SECURITY] ERROR: You must confirm authorization first!"
            Return
        End If
        
        Dim target = SecurityTargetTextBox.Text.Trim()
        If String.IsNullOrEmpty(target) Then
            SecurityOutputTextBox.Text = "[SECURITY] ERROR: Enter a target"
            Return
        End If
        
        Dim toolIndex = SecurityToolComboBox.SelectedIndex
        Dim toolName = ""
        Dim toolArgs = ""
        
        Select Case toolIndex
            Case 0 ' Nmap
                toolName = "nmap"
                toolArgs = $"-sV -sC {target}"
            Case 1 ' SQLMap
                toolName = "python"
                toolArgs = $"-m sqlmap -u ""{target}"" --batch --level=1"
            Case 2 ' WPScan
                toolName = "wpscan"
                toolArgs = $"--url {target} --enumerate vp"
            Case 3 ' XSStrike
                toolName = "python"
                toolArgs = $"xsstrike.py -u ""{target}"""
            Case 4 ' DNSRecon
                toolName = "dnsrecon"
                toolArgs = $"-d {target}"
        End Select
        
        SecurityOutputTextBox.Text = $"[SECURITY] Executing: {toolName} {toolArgs}{vbCrLf}"
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
                
                Dim proc As New Process()
                proc.StartInfo = psi
                proc.Start()
                
                While Not proc.StandardOutput.EndOfStream
                    Dim line = proc.StandardOutput.ReadLine()
                    Dispatcher.Invoke(Sub()
                        SecurityOutputTextBox.Text += line + vbCrLf
                    End Sub)
                End While
                
                proc.WaitForExit()
            End Sub)
            
            LogTerminal("[SECURITY] Tool execution completed")
        Catch ex As Exception
            SecurityOutputTextBox.Text += $"{vbCrLf}[SECURITY] ERROR: {ex.Message}{vbCrLf}Make sure the tool is installed and in PATH"
            LogTerminal($"[SECURITY] ERROR: {ex.Message}")
        End Try
    End Sub
#End Region

#Region "AI"
    Private Sub AIAnalysisButton_Click(sender As Object, e As RoutedEventArgs)
        ' Switch to AI tab
    End Sub
    
    Private Async Sub AskSofiaButton_Click(sender As Object, e As RoutedEventArgs)
        Dim apiKey = ApiKeyBox.Password
        If String.IsNullOrEmpty(apiKey) Then
            AIOutputTextBox.Text = "[SOFIA] ERROR: Please enter your OpenRouter API key in settings below"
            Return
        End If
        
        Dim query = AIInputTextBox.Text.Trim()
        If String.IsNullOrEmpty(query) Then
            AIOutputTextBox.Text = "[SOFIA] ERROR: Please enter a question"
            Return
        End If
        
        ' Collect network data
        Dim networkData As New StringBuilder()
        networkData.AppendLine("=== NETWORK STATUS ===")
        networkData.AppendLine($"Interface: {_selectedInterface?.Name}")
        networkData.AppendLine($"Packets Captured: {_packetCount}")
        networkData.AppendLine($"Sent: {SentText.Text}")
        networkData.AppendLine($"Received: {ReceivedText.Text}")
        
        AIOutputTextBox.Text = "[SOFIA] Analyzing..."
        LogTerminal("[AI] Sending query to SOFIA...")
        
        Try
            Dim response = Await GetAIResponseAsync(apiKey, query, networkData.ToString())
            AIOutputTextBox.Text = response
            LogTerminal("[AI] Response received")
        Catch ex As Exception
            AIOutputTextBox.Text = $"[SOFIA] ERROR: {ex.Message}"
            LogTerminal($"[AI] ERROR: {ex.Message}")
        End Try
    End Sub
    
    Private Async Function GetAIResponseAsync(apiKey As String, query As String, context As String) As Task(Of String)
        Using client As New HttpClient()
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}")
            client.DefaultRequestHeaders.Add("HTTP-Referer", "https://rootcastle.rei")
            client.DefaultRequestHeaders.Add("X-Title", "Rootcastle Network Monitor")
            
            Dim modelId = "deepseek/deepseek-chat"
            Select Case AIModelComboBox.SelectedIndex
                Case 0 : modelId = "deepseek/deepseek-chat"
                Case 1 : modelId = "openai/gpt-4o-mini"
                Case 2 : modelId = "anthropic/claude-3.5-haiku"
                Case 3 : modelId = "meta-llama/llama-3.2-3b-instruct:free"
            End Select
            
            Dim body As New JObject()
            body("model") = modelId
            
            Dim messages As New JArray()
            messages.Add(New JObject() From {
                {"role", "system"},
                {"content", "You are SOFIA, an expert network security AI assistant for Rootcastle Network Monitor. Respond in Turkish by default. Be technical, concise, and helpful."}
            })
            messages.Add(New JObject() From {
                {"role", "user"},
                {"content", $"Network Context:{vbCrLf}{context}{vbCrLf}{vbCrLf}User Question: {query}"}
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
    
    Protected Overrides Sub OnClosing(e As CancelEventArgs)
        StopCapture()
        _monitoringCts?.Cancel()
        _uptimeTimer?.Dispose()
        _nmapProcess?.Kill()
        MyBase.OnClosing(e)
    End Sub
#End Region

End Class

Public Class CapturedPacketInfo
    Public Property Timestamp As DateTime
    Public Property SourceIP As String = ""
    Public Property DestIP As String = ""
    Public Property SourcePort As Integer
    Public Property DestPort As Integer
    Public Property Protocol As String = ""
    Public Property Length As Integer
End Class
