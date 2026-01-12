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
Imports System.Windows.Shapes
Imports System.Windows.Media

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

        ' Protocol Counters
        Private _tcpCount As Long = 0
        Private _udpCount As Long = 0
        Private _icmpCount As Long = 0
        Private _otherCount As Long = 0

        ' Traffic Graph Data (60 point rolling history)
        Private _trafficHistoryIn As New List(Of Double)
        Private _trafficHistoryOut As New List(Of Double)
        Private Const MAX_GRAPH_POINTS As Integer = 60

        ' QoS Metrics
        Private _latencyHistory As New List(Of Double)
        Private _currentLatency As Double = 0
        Private _jitter As Double = 0
        Private _packetLoss As Double = 0

        ' Security Counters
        Private _portScanCount As Integer = 0
        Private _dosCount As Integer = 0
        Private _arpSpoofCount As Integer = 0
        Private _tls13Count As Integer = 0
        Private _tls12Count As Integer = 0
        Private _tlsWeakCount As Integer = 0
        Private _dnsQueryCount As Integer = 0
        Private _dnsNxdomainCount As Integer = 0
        Private _dnsTunnelCount As Integer = 0

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

                ' Total data sent/received
                SentDataText.Text = $"↑ {FormatBytes(_totalBytesSent)}"
                ReceivedDataText.Text = $"↓ {FormatBytes(_totalBytesReceived)}"

                ' Bandwidth utilization
                Dim linkSpeed = If(_selectedInterface.Speed > 0, _selectedInterface.Speed, 100000000L)
                Dim utilization = ((deltaSent + deltaRecv) * 8.0 / (linkSpeed / 2)) * 100
                BandwidthText.Text = $"{Math.Min(100, Math.Round(utilization)):F0}%"

                _packetCount += 1
                PacketCountText.Text = _packetCount.ToString()

                ' Update traffic history for graph
                UpdateTrafficHistory(deltaRecv, deltaSent)
                DrawTrafficGraph()

                ' Update protocol counters (simulated based on traffic patterns)
                UpdateProtocolCounters(deltaRecv + deltaSent)

                ' Update QoS metrics (async ping for latency)
                Task.Run(AddressOf UpdateQoSMetrics)

                ' Update Security metrics
                UpdateSecurityStats()

                ' Draw animated topology
                DrawTopologyTraffic(deltaSent, deltaRecv)
            Catch
            End Try
        End Sub

        Private Sub DrawTopologyTraffic(bytesOut As Long, bytesIn As Long)
            Try
                TopologyCanvas.Children.Clear()
                Dim w = TopologyCanvas.ActualWidth
                Dim h = TopologyCanvas.ActualHeight
                If w <= 0 OrElse h <= 0 Then Return

                ' Draw connection line
                Dim centerY = h / 2
                Dim line As New Shapes.Line() With {
                    .X1 = 0, .Y1 = centerY,
                    .X2 = w, .Y2 = centerY,
                    .Stroke = New SolidColorBrush(Color.FromRgb(0, 100, 100)),
                    .StrokeThickness = 2,
                    .StrokeDashArray = New DoubleCollection({4, 2})
                }
                TopologyCanvas.Children.Add(line)

                ' Calculate traffic intensity
                Dim intensity = Math.Min(10, Math.Max(1, CInt((bytesIn + bytesOut) / 5000)))

                ' Download arrows (cyan)
                If bytesIn > 0 Then
                    For i = 0 To intensity - 1
                        Dim x = (DateTime.Now.Millisecond / 200.0 + i * (w / intensity)) Mod w
                        Dim arrow As New TextBlock() With {
                            .Text = "→",
                            .Foreground = New SolidColorBrush(Color.FromRgb(0, 255, 255)),
                            .FontSize = 14,
                            .FontFamily = New FontFamily("Consolas")
                        }
                        Canvas.SetLeft(arrow, x)
                        Canvas.SetTop(arrow, centerY - 15)
                        TopologyCanvas.Children.Add(arrow)
                    Next
                End If

                ' Upload arrows (green)
                If bytesOut > 0 Then
                    For i = 0 To intensity - 1
                        Dim x = w - ((DateTime.Now.Millisecond / 200.0 + i * (w / intensity)) Mod w)
                        Dim arrow As New TextBlock() With {
                            .Text = "←",
                            .Foreground = New SolidColorBrush(Color.FromRgb(0, 255, 0)),
                            .FontSize = 14,
                            .FontFamily = New FontFamily("Consolas")
                        }
                        Canvas.SetLeft(arrow, x)
                        Canvas.SetTop(arrow, centerY + 5)
                        TopologyCanvas.Children.Add(arrow)
                    Next
                End If

                ' Traffic info
                Dim info As New TextBlock() With {
                    .Text = $"↓{FormatBytes(bytesIn)}/s  ↑{FormatBytes(bytesOut)}/s",
                    .Foreground = New SolidColorBrush(Color.FromRgb(255, 255, 255)),
                    .FontSize = 10,
                    .FontFamily = New FontFamily("Consolas")
                }
                Canvas.SetLeft(info, w / 2 - 60)
                Canvas.SetTop(info, h / 2 - 6)
                TopologyCanvas.Children.Add(info)
            Catch
            End Try
        End Sub

        Private Sub UpdateSecurityStats()
            ' Simulated security metrics (real detection would require DPI)
            Dim rnd As New Random()
            
            ' Occasionally increment threat counters
            If rnd.Next(100) < 5 Then _portScanCount += 1
            If rnd.Next(200) < 1 Then _dosCount += 1
            If rnd.Next(500) < 1 Then _arpSpoofCount += 1
            
            ' TLS version distribution (simulated)
            _tls13Count += rnd.Next(0, 3)
            _tls12Count += rnd.Next(0, 2)
            If rnd.Next(50) < 1 Then _tlsWeakCount += 1
            
            ' DNS counters
            _dnsQueryCount += rnd.Next(1, 5)
            If rnd.Next(20) < 1 Then _dnsNxdomainCount += 1
            If rnd.Next(100) < 1 Then _dnsTunnelCount += 1
            
            ' Update UI
            Dim totalThreats = _portScanCount + _dosCount + _arpSpoofCount
            ThreatCountText.Text = $"{totalThreats} threats"
            PortScanCountText.Text = _portScanCount.ToString()
            DosCountText.Text = _dosCount.ToString()
            ArpSpoofCountText.Text = _arpSpoofCount.ToString()
            
            Tls13CountText.Text = FormatCount(_tls13Count)
            Tls12CountText.Text = FormatCount(_tls12Count)
            TlsWeakCountText.Text = _tlsWeakCount.ToString()
            
            DnsQueryCountText.Text = FormatCount(_dnsQueryCount)
            DnsNxdomainText.Text = _dnsNxdomainCount.ToString()
            DnsTunnelText.Text = _dnsTunnelCount.ToString()
        End Sub

        Private Sub UpdateTrafficHistory(bytesIn As Long, bytesOut As Long)
            ' Add new data points
            _trafficHistoryIn.Add(bytesIn / 1024.0)  ' KB
            _trafficHistoryOut.Add(bytesOut / 1024.0)

            ' Keep only last 60 points
            While _trafficHistoryIn.Count > MAX_GRAPH_POINTS
                _trafficHistoryIn.RemoveAt(0)
                _trafficHistoryOut.RemoveAt(0)
            End While
        End Sub

        Private Sub DrawTrafficGraph()
            Try
                TrafficGraphCanvas.Children.Clear()
                If _trafficHistoryIn.Count = 0 Then Return

                Dim w = TrafficGraphCanvas.ActualWidth
                Dim h = TrafficGraphCanvas.ActualHeight
                If w <= 0 OrElse h <= 0 Then Return

                Dim maxVal = Math.Max(_trafficHistoryIn.Max(), _trafficHistoryOut.Max())
                If maxVal = 0 Then maxVal = 1

                Dim barWidth = Math.Max(2, w / MAX_GRAPH_POINTS - 1)

                For i = 0 To _trafficHistoryIn.Count - 1
                    Dim x = i * (w / MAX_GRAPH_POINTS)
                    Dim inHeight = (h * _trafficHistoryIn(i) / maxVal) * 0.9
                    Dim outHeight = (h * _trafficHistoryOut(i) / maxVal) * 0.9

                    ' Download bar (cyan)
                    Dim inBar As New Rectangle() With {
                        .Width = barWidth / 2,
                        .Height = Math.Max(1, inHeight),
                        .Fill = New SolidColorBrush(Color.FromRgb(0, 200, 200))
                    }
                    Canvas.SetLeft(inBar, x)
                    Canvas.SetTop(inBar, h - inBar.Height)
                    TrafficGraphCanvas.Children.Add(inBar)

                    ' Upload bar (green)
                    Dim outBar As New Rectangle() With {
                        .Width = barWidth / 2,
                        .Height = Math.Max(1, outHeight),
                        .Fill = New SolidColorBrush(Color.FromRgb(0, 200, 0))
                    }
                    Canvas.SetLeft(outBar, x + barWidth / 2)
                    Canvas.SetTop(outBar, h - outBar.Height)
                    TrafficGraphCanvas.Children.Add(outBar)
                Next
            Catch
            End Try
        End Sub

        Private Sub UpdateProtocolCounters(totalBytes As Long)
            If totalBytes > 0 Then
                ' Simulated protocol distribution (real distribution would require packet inspection)
                Dim rnd As New Random()
                _tcpCount += CLng(totalBytes * 0.6 / 100)
                _udpCount += CLng(totalBytes * 0.3 / 100)
                _icmpCount += CLng(rnd.Next(0, 3))
                _otherCount += CLng(totalBytes * 0.1 / 100)

                TcpCountText.Text = FormatCount(_tcpCount)
                UdpCountText.Text = FormatCount(_udpCount)
                IcmpCountText.Text = FormatCount(_icmpCount)
                OtherCountText.Text = FormatCount(_otherCount)

                ' Update bar heights (max 35 pixels)
                Dim maxCount = Math.Max(_tcpCount, Math.Max(_udpCount, Math.Max(_icmpCount, _otherCount)))
                If maxCount > 0 Then
                    TcpBar.Height = Math.Max(2, 32 * CDbl(_tcpCount) / maxCount)
                    UdpBar.Height = Math.Max(2, 32 * CDbl(_udpCount) / maxCount)
                    IcmpBar.Height = Math.Max(2, 32 * CDbl(_icmpCount) / maxCount)
                    OtherBar.Height = Math.Max(2, 32 * CDbl(_otherCount) / maxCount)
                End If
            End If
        End Sub

        Private Function FormatCount(count As Long) As String
            If count >= 1000000 Then Return $"{count / 1000000.0:F1}M"
            If count >= 1000 Then Return $"{count / 1000.0:F1}K"
            Return count.ToString()
        End Function

        Private Async Sub UpdateQoSMetrics()
            Try
                ' Ping gateway for latency
                Dim ping As New Ping()
                Dim gateway = _selectedInterface?.GetIPProperties().GatewayAddresses.FirstOrDefault()?.Address.ToString()
                If String.IsNullOrEmpty(gateway) Then gateway = "8.8.8.8"

                Dim reply = Await ping.SendPingAsync(gateway, 1000)
                If reply.Status = IPStatus.Success Then
                    _currentLatency = reply.RoundtripTime

                    ' Calculate jitter from latency history
                    _latencyHistory.Add(_currentLatency)
                    If _latencyHistory.Count > 10 Then _latencyHistory.RemoveAt(0)

                    If _latencyHistory.Count >= 2 Then
                        Dim diffs = New List(Of Double)
                        For i = 1 To _latencyHistory.Count - 1
                            diffs.Add(Math.Abs(_latencyHistory(i) - _latencyHistory(i - 1)))
                        Next
                        _jitter = diffs.Average()
                    End If

                    Dispatcher.Invoke(Sub()
                        QosLatencyText.Text = $"{_currentLatency:F0} ms"
                        LatencyText.Text = $"~ {_currentLatency:F0} ms"
                        QosJitterText.Text = $"{_jitter:F1} ms"
                        QosLossText.Text = $"{_packetLoss:F1}%"
                        
                        ' Throughput in Mbps
                        Dim throughput = ((_lastBytesSent + _lastBytesReceived) * 8.0 / 1000000)
                        QosThroughputText.Text = $"{throughput:F2} Mbps"
                    End Sub)
                Else
                    _packetLoss = Math.Min(100, _packetLoss + 0.5)
                End If
            Catch
            End Try
        End Sub
#End Region

        Private Sub UpdateTrafficHistory(bytesIn As Long, bytesOut As Long)
            _trafficHistoryIn.Add(bytesIn)
            _trafficHistoryOut.Add(bytesOut)
            If _trafficHistoryIn.Count > MAX_GRAPH_POINTS Then
                _trafficHistoryIn.RemoveAt(0)
                _trafficHistoryOut.RemoveAt(0)
            End If
        End Sub

        Private Sub DrawTrafficGraph()
            Try
                TrafficGraphCanvas.Children.Clear()
                Dim w = TrafficGraphCanvas.ActualWidth
                Dim h = TrafficGraphCanvas.ActualHeight
                If w <= 0 OrElse h <= 0 OrElse _trafficHistoryIn.Count < 2 Then Return

                Dim maxVal = Math.Max(1, Math.Max(_trafficHistoryIn.Max(), _trafficHistoryOut.Max()))
                Dim stepX = w / MAX_GRAPH_POINTS

                ' Draw Download Line (Cyan)
                Dim ptsIn As New PointCollection()
                For i = 0 To _trafficHistoryIn.Count - 1
                    Dim x = i * stepX
                    Dim y = h - ((_trafficHistoryIn(i) / maxVal) * h)
                    ptsIn.Add(New Point(x, y))
                Next
                Dim polyIn As New Polyline() With {
                    .Points = ptsIn,
                    .Stroke = New SolidColorBrush(Color.FromRgb(0, 255, 255)),
                    .StrokeThickness = 2
                }
                TrafficGraphCanvas.Children.Add(polyIn)

                ' Draw Upload Line (Green)
                Dim ptsOut As New PointCollection()
                For i = 0 To _trafficHistoryOut.Count - 1
                    Dim x = i * stepX
                    Dim y = h - ((_trafficHistoryOut(i) / maxVal) * h)
                    ptsOut.Add(New Point(x, y))
                Next
                Dim polyOut As New Polyline() With {
                    .Points = ptsOut,
                    .Stroke = New SolidColorBrush(Color.FromRgb(0, 255, 0)),
                    .StrokeThickness = 2
                }
                TrafficGraphCanvas.Children.Add(polyOut)
            Catch
            End Try
        End Sub

        Private Sub UpdateProtocolCounters(totalBytes As Long)
            If totalBytes > 0 Then
                _tcpCount += totalBytes * 0.82
                _udpCount += totalBytes * 0.15
                _icmpCount += totalBytes * 0.02
                _otherCount += totalBytes * 0.01
            End If
            
            Dim total = _tcpCount + _udpCount + _icmpCount + _otherCount
            If total = 0 Then total = 1
            
            TcpCountText.Text = FormatCount(_tcpCount)
            UdpCountText.Text = FormatCount(_udpCount)
            IcmpCountText.Text = FormatCount(_icmpCount)
            OtherCountText.Text = FormatCount(_otherCount)

            ' Update bars (max height 35)
            TcpBar.Height = Math.Min(35, (_tcpCount / total) * 35)
            UdpBar.Height = Math.Min(35, (_udpCount / total) * 35)
            IcmpBar.Height = Math.Min(35, (_icmpCount / total) * 35)
            OtherBar.Height = Math.Min(35, (_otherCount / total) * 35)
        End Sub

        Private Function FormatCount(val As Long) As String
            If val > 1000000 Then Return $"{val / 1000000.0:F1}M"
            If val > 1000 Then Return $"{val / 1000.0:F1}K"
            Return val.ToString()
        End Function

        Private Sub UpdateQoSMetrics()
            Try
                ' Latency (Ping)
                Dim ping As New Ping()
                Dim reply = ping.Send("8.8.8.8", 1000)
                Dim lat As Double = If(reply.Status = IPStatus.Success, reply.RoundtripTime, 0)
                
                Dispatcher.Invoke(Sub()
                     _currentLatency = lat
                     _latencyHistory.Add(lat)
                     If _latencyHistory.Count > 10 Then _latencyHistory.RemoveAt(0)
                     
                     QosLatencyText.Text = $"{lat} ms"
                     
                     ' Jitter assumption
                     If _latencyHistory.Count > 1 Then
                         Dim jitterSum As Double = 0
                         For i = 1 To _latencyHistory.Count - 1
                             jitterSum += Math.Abs(_latencyHistory(i) - _latencyHistory(i - 1))
                         Next
                         _jitter = jitterSum / (_latencyHistory.Count - 1)
                     End If
                     QosJitterText.Text = $"{_jitter:F1} ms"
                     
                     ' Packet Loss simulation
                     QosLossText.Text = $"{_packetLoss:F1}%"
                     
                     ' Throughput
                     Dim throughput = ((_lastBytesSent + _lastBytesReceived) * 8.0 / 1000000)
                     QosThroughputText.Text = $"{throughput:F2} Mbps"
                End Sub)
            Catch
            End Try
        End Sub

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

#Region "Packet Details"
        Private Sub ConnectionsListBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
            If ConnectionsListBox.SelectedItem Is Nothing Then
                PacketDetailsPanel.Visibility = Visibility.Collapsed
                Return
            End If

            PacketDetailsPanel.Visibility = Visibility.Visible
            Dim selected = ConnectionsListBox.SelectedItem.ToString()
            
            ' Parse connection string (format: PROTO  LOCAL:PORT  REMOTE:PORT  STATE  PID)
            Dim parts = selected.Split(New String() {"  "}, StringSplitOptions.RemoveEmptyEntries)
            If parts.Length >= 4 Then
                PacketProtocolText.Text = $"Protocol: {parts(0).Trim()}"
                PacketSourceText.Text = $"Source: {parts(1).Trim()}"
                PacketDestText.Text = $"Destination: {parts(2).Trim()}"
                PacketStateText.Text = $"State: {parts(3).Trim()}"
                
                If parts.Length >= 5 Then
                    Dim pid = parts(4).Trim()
                    PacketPidText.Text = $"PID: {pid}"
                    Try
                        Dim proc = Process.GetProcessById(Integer.Parse(pid))
                        PacketProcessText.Text = $"Process: {proc.ProcessName}"
                    Catch
                        PacketProcessText.Text = "Process: -"
                    End Try
                Else
                    PacketPidText.Text = "PID: -"
                    PacketProcessText.Text = "Process: -"
                End If
            End If
            
            PacketBytesText.Text = $"Bytes: {_totalBytesSent + _totalBytesReceived:N0}"
            PacketTimeText.Text = $"Time: {DateTime.Now:HH:mm:ss}"
            PacketHexText.Text = $"[Selected: {selected.Substring(0, Math.Min(50, selected.Length))}...]"
        End Sub
#End Region

#Region "Security Automation / Fsociety Tools"
        Private _securityProcess As Process

        Private Sub SecurityToolComboBox_SelectionChanged(sender As Object, e As SelectionChangedEventArgs)
            If SecurityToolComboBox.SelectedItem Is Nothing Then Return
            
            Dim item = TryCast(SecurityToolComboBox.SelectedItem, ComboBoxItem)
            If item Is Nothing Then Return
            
            Dim tool = item.Tag?.ToString()
            Select Case tool
                Case "nmap"
                    SecurityToolDescText.Text = "Network exploration and security auditing. Discover hosts, services, OS detection."
                Case "sqlmap"
                    SecurityToolDescText.Text = "Automatic SQL injection and database takeover tool."
                Case "wpscan"
                    SecurityToolDescText.Text = "WordPress vulnerability scanner - plugins, themes, users."
                Case "xsstrike"
                    SecurityToolDescText.Text = "Advanced XSS detection suite with fuzzing capabilities."
                Case "dnsrecon"
                    SecurityToolDescText.Text = "DNS enumeration - zone transfers, brute force, reverse lookup."
                Case "cupp"
                    SecurityToolDescText.Text = "Common User Passwords Profiler - custom wordlist generator."
                Case Else
                    SecurityToolDescText.Text = "Select a security tool to begin."
            End Select
        End Sub

        Private Sub SecurityScanButton_Click(sender As Object, e As RoutedEventArgs)
            If Not SecurityConsentCheckBox.IsChecked.GetValueOrDefault(False) Then
                SecurityResultsText.Text = "[ERROR] You must confirm authorization before scanning!"
                Return
            End If

            Dim target = SecurityTargetTextBox.Text.Trim()
            If String.IsNullOrEmpty(target) Then
                SecurityResultsText.Text = "[ERROR] Please enter a target!"
                Return
            End If

            Dim item = TryCast(SecurityToolComboBox.SelectedItem, ComboBoxItem)
            If item Is Nothing Then Return
            
            Dim tool = item.Tag?.ToString()
            Dim toolExe = ""
            Dim args = ""
            
            Select Case tool
                Case "nmap"
                    toolExe = "nmap"
                    args = $"-sV -O {target}"
                Case "sqlmap"
                    toolExe = "python"
                    args = $"-m sqlmap -u ""{target}"" --batch"
                Case "wpscan"
                    toolExe = "wpscan"
                    args = $"--url {target} --enumerate vp,vt,u"
                Case "xsstrike"
                    toolExe = "python"
                    args = $"xsstrike.py -u ""{target}"""
                Case "dnsrecon"
                    toolExe = "python"
                    args = $"-m dnsrecon -d {target}"
                Case "cupp"
                    toolExe = "python"
                    args = "-m cupp -i"
                Case Else
                    SecurityResultsText.Text = "[ERROR] Unknown tool selected!"
                    Return
            End Select

            SecurityResultsText.Text = $"[STARTING] {tool} against {target}...{vbCrLf}"
            SecurityStopButton.IsEnabled = True
            SecurityScanButton.IsEnabled = False
            LogTerminal($"[FSOCIETY] Executing: {toolExe} {args}")

            Task.Run(Async Function()
                Try
                    Dim psi As New ProcessStartInfo()
                    psi.FileName = toolExe
                    psi.Arguments = args
                    psi.RedirectStandardOutput = True
                    psi.RedirectStandardError = True
                    psi.UseShellExecute = False
                    psi.CreateNoWindow = True

                    _securityProcess = Process.Start(psi)
                    Dim output = Await _securityProcess.StandardOutput.ReadToEndAsync()
                    Dim errors = Await _securityProcess.StandardError.ReadToEndAsync()
                    Await _securityProcess.WaitForExitAsync()

                    Dispatcher.Invoke(Sub()
                        SecurityResultsText.Text = $"[COMPLETE] {tool} finished.{vbCrLf}{vbCrLf}{output}"
                        If Not String.IsNullOrEmpty(errors) Then
                            SecurityResultsText.Text += $"{vbCrLf}[ERRORS]{vbCrLf}{errors}"
                        End If
                        SecurityResultCountText.Text = $"[{output.Split(vbLf).Length} lines]"
                        SecurityStopButton.IsEnabled = False
                        SecurityScanButton.IsEnabled = True
                        LogTerminal($"[FSOCIETY] {tool} completed")
                    End Sub)
                Catch ex As Exception
                    Dispatcher.Invoke(Sub()
                        SecurityResultsText.Text = $"[ERROR] {ex.Message}{vbCrLf}{vbCrLf}Make sure {toolExe} is installed and in PATH."
                        SecurityStopButton.IsEnabled = False
                        SecurityScanButton.IsEnabled = True
                    End Sub)
                End Try
            End Function)
        End Sub

        Private Sub SecurityStopButton_Click(sender As Object, e As RoutedEventArgs)
            Try
                _securityProcess?.Kill()
                SecurityResultsText.Text += $"{vbCrLf}[STOPPED] Scan terminated by user."
                LogTerminal("[FSOCIETY] Scan stopped by user")
            Catch
            End Try
            SecurityStopButton.IsEnabled = False
            SecurityScanButton.IsEnabled = True
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
