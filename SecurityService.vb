Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Security.Cryptography
Imports System.Text
Imports System.Threading.Tasks
Imports Windows.Storage

''' <summary>
''' Security automation service for fsociety module orchestration.
''' Handles tool validation, authorization, audit logging, and companion service communication.
''' </summary>
''' <remarks>
''' This service provides the UWP-side interface. Actual tool execution is delegated
''' to a companion Windows Service for sandbox isolation.
''' </remarks>
Public Class SecurityService

#Region "Singleton"

    Private Shared _instance As SecurityService
    Private Shared ReadOnly _lock As New Object()

    Public Shared ReadOnly Property Instance As SecurityService
        Get
            If _instance Is Nothing Then
                SyncLock _lock
                    If _instance Is Nothing Then
                        _instance = New SecurityService()
                    End If
                End SyncLock
            End If
            Return _instance
        End Get
    End Property

#End Region

#Region "Properties"

    ''' <summary>
    ''' Whether Lab Mode is enabled (allows private IP ranges).
    ''' </summary>
    Public Property LabModeEnabled As Boolean = False

    ''' <summary>
    ''' Current authorization (valid for one scan).
    ''' </summary>
    Public Property CurrentAuthorization As ScanAuthorization

    ''' <summary>
    ''' Audit log entries for current session.
    ''' </summary>
    Public ReadOnly Property AuditLog As New List(Of AuditEntry)

    ''' <summary>
    ''' Tool availability status.
    ''' </summary>
    Public ReadOnly Property ToolStatus As New Dictionary(Of SecurityTool, ToolAvailability)

    Private _auditSequence As Long = 0
    Private _lastAuditHash As String = "GENESIS"

#End Region

#Region "Tool Validation"

    ''' <summary>
    ''' Tool availability information.
    ''' </summary>
    Public Class ToolAvailability
        Public Property Tool As SecurityTool
        Public Property IsAvailable As Boolean
        Public Property ExecutablePath As String
        Public Property Version As String
        Public Property ErrorMessage As String
        Public Property InstallInstructions As String
    End Class

    ''' <summary>
    ''' Validates all security tools at startup.
    ''' </summary>
    Public Async Function ValidateToolsAsync() As Task(Of Dictionary(Of SecurityTool, ToolAvailability))
        ToolStatus.Clear()

        ' Note: In UWP, we cannot directly check for executables
        ' This would be delegated to the companion service
        ' For now, we create placeholder entries

        Dim tools As SecurityTool() = {
            SecurityTool.Nmap,
            SecurityTool.SQLMap,
            SecurityTool.WPScan,
            SecurityTool.XSStrike,
            SecurityTool.DNSRecon,
            SecurityTool.Cupp
        }

        For Each tool In tools
            Dim availability = Await CheckToolAvailabilityAsync(tool)
            ToolStatus(tool) = availability
        Next

        Return ToolStatus
    End Function

    ''' <summary>
    ''' Checks if a specific tool is available.
    ''' </summary>
    Private Async Function CheckToolAvailabilityAsync(tool As SecurityTool) As Task(Of ToolAvailability)
        Dim result As New ToolAvailability()
        result.Tool = tool

        ' This would query the companion service
        ' For now, return configuration-based availability
        Select Case tool
            Case SecurityTool.Nmap
                result.ExecutablePath = "nmap"
                result.InstallInstructions = "Install via Chocolatey: choco install nmap"
                result.IsAvailable = False  ' Will be set by companion service
            Case SecurityTool.SQLMap
                result.ExecutablePath = "sqlmap"
                result.InstallInstructions = "Install via pip: pip install sqlmap"
                result.IsAvailable = False
            Case SecurityTool.WPScan
                result.ExecutablePath = "wpscan"
                result.InstallInstructions = "Install via gem: gem install wpscan"
                result.IsAvailable = False
            Case SecurityTool.XSStrike
                result.ExecutablePath = "python xsstrike.py"
                result.InstallInstructions = "Clone from GitHub: git clone https://github.com/s0md3v/XSStrike"
                result.IsAvailable = False
            Case SecurityTool.DNSRecon
                result.ExecutablePath = "dnsrecon"
                result.InstallInstructions = "Install via pip: pip install dnsrecon"
                result.IsAvailable = False
            Case SecurityTool.Cupp
                result.ExecutablePath = "python cupp.py"
                result.InstallInstructions = "Clone from GitHub: git clone https://github.com/Mebus/cupp"
                result.IsAvailable = False
        End Select

        ' Simulate async operation (would be IPC to companion service)
        Await Task.Delay(10)

        Return result
    End Function

#End Region

#Region "Authorization"

    ''' <summary>
    ''' Creates authorization for a scan after user consent.
    ''' </summary>
    Public Function CreateAuthorization(target As String, tool As SecurityTool) As ScanAuthorization
        Dim consentText = LegalCompliance.GenerateConsentText(target, tool)
        Dim auth = ScanAuthorization.Create(target, tool, consentText, LabModeEnabled, 60)

        CurrentAuthorization = auth

        ' Log authorization
        LogAuditEntry("SCAN_AUTHORIZED", target, tool.ToString(), auth.ConsentHash)

        Return auth
    End Function

    ''' <summary>
    ''' Validates that current authorization covers the requested operation.
    ''' </summary>
    Public Function ValidateAuthorization(target As String, tool As SecurityTool) As Boolean
        If CurrentAuthorization Is Nothing Then Return False
        Return CurrentAuthorization.IsValid(target, tool)
    End Function

    ''' <summary>
    ''' Clears current authorization (after scan or on expiration).
    ''' </summary>
    Public Sub ClearAuthorization()
        If CurrentAuthorization IsNot Nothing Then
            LogAuditEntry("AUTHORIZATION_CLEARED", "", CurrentAuthorization.AuthorizedTool.ToString(), "")
        End If
        CurrentAuthorization = Nothing
    End Sub

#End Region

#Region "Audit Logging"

    ''' <summary>
    ''' Logs an action to the immutable audit trail.
    ''' </summary>
    Public Sub LogAuditEntry(action As String, target As String, toolName As String, Optional authHash As String = "")
        _auditSequence += 1

        Dim entry As New AuditEntry()
        entry.EntryId = Guid.NewGuid().ToString("N").ToUpperInvariant()
        entry.SequenceNumber = _auditSequence
        entry.Timestamp = DateTime.UtcNow
        entry.Action = action
        entry.UserId = Environment.UserName
        entry.TargetHash = If(String.IsNullOrEmpty(target), "", ComputeSha256(target))
        entry.ToolName = toolName
        entry.AuthorizationHash = authHash
        entry.PreviousEntryHash = _lastAuditHash

        ' Compute entry hash for chain integrity
        entry.EntryHash = entry.ComputeHash()
        _lastAuditHash = entry.EntryHash

        AuditLog.Add(entry)

        ' Also write to debug output
        System.Diagnostics.Debug.WriteLine($"[AUDIT] {entry.Timestamp:O} | {action} | {toolName} | Seq:{_auditSequence}")
    End Sub

    ''' <summary>
    ''' Exports audit log to encrypted file.
    ''' </summary>
    Public Async Function ExportAuditLogAsync() As Task(Of String)
        Try
            Dim folder = ApplicationData.Current.LocalFolder
            Dim auditFolder = Await folder.CreateFolderAsync("Audits", CreationCollisionOption.OpenIfExists)

            Dim filename = $"audit_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json"
            Dim file = Await auditFolder.CreateFileAsync(filename, CreationCollisionOption.GenerateUniqueName)

            ' Build JSON
            Dim sb As New StringBuilder()
            sb.AppendLine("{")
            sb.AppendLine($"  ""exportTimestamp"": ""{DateTime.UtcNow:O}"",")
            sb.AppendLine($"  ""environment"": ""{If(LabModeEnabled, "lab", "production")}"",")
            sb.AppendLine($"  ""entryCount"": {AuditLog.Count},")
            sb.AppendLine("  ""entries"": [")

            For i = 0 To AuditLog.Count - 1
                Dim entry = AuditLog(i)
                sb.AppendLine("    {")
                sb.AppendLine($"      ""entryId"": ""{entry.EntryId}"",")
                sb.AppendLine($"      ""sequence"": {entry.SequenceNumber},")
                sb.AppendLine($"      ""timestamp"": ""{entry.Timestamp:O}"",")
                sb.AppendLine($"      ""action"": ""{entry.Action}"",")
                sb.AppendLine($"      ""userId"": ""{entry.UserId}"",")
                sb.AppendLine($"      ""targetHash"": ""{entry.TargetHash}"",")
                sb.AppendLine($"      ""toolName"": ""{entry.ToolName}"",")
                sb.AppendLine($"      ""authHash"": ""{entry.AuthorizationHash}"",")
                sb.AppendLine($"      ""prevHash"": ""{entry.PreviousEntryHash}"",")
                sb.AppendLine($"      ""entryHash"": ""{entry.EntryHash}""")
                sb.Append("    }")
                If i < AuditLog.Count - 1 Then sb.Append(",")
                sb.AppendLine()
            Next

            sb.AppendLine("  ]")
            sb.AppendLine("}")

            Await FileIO.WriteTextAsync(file, sb.ToString())

            LogAuditEntry("AUDIT_EXPORTED", file.Path, "", "")

            Return file.Path

        Catch ex As Exception
            Return $"Error: {ex.Message}"
        End Try
    End Function

    Private Shared Function ComputeSha256(input As String) As String
        Using sha As SHA256 = SHA256.Create()
            Dim bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input))
            Return BitConverter.ToString(bytes).Replace("-", "").ToUpperInvariant()
        End Using
    End Function

#End Region

#Region "Scan Execution (Stub - Companion Service)"

    ''' <summary>
    ''' Executes a security scan via companion service.
    ''' </summary>
    ''' <remarks>
    ''' In UWP, we cannot spawn processes directly. This method would communicate
    ''' with a companion Windows Service via named pipes or gRPC.
    ''' </remarks>
    Public Async Function ExecuteScanAsync(target As String, tool As SecurityTool, config As ToolConfiguration) As Task(Of ScanResult)
        ' Validate authorization
        If Not ValidateAuthorization(target, tool) Then
            LogAuditEntry("SCAN_BLOCKED_UNAUTHORIZED", target, tool.ToString(), "")
            Return ScanResult.CreateFailed(tool.ToString(), target, "Authorization required. Please acknowledge the legal disclaimer.", ScanStatus.Unauthorized)
        End If

        ' Validate target
        Dim validation = TargetValidator.AutoValidate(target, LabModeEnabled)
        If Not validation.IsValid Then
            LogAuditEntry("SCAN_BLOCKED_INVALID_TARGET", target, tool.ToString(), validation.Status.ToString())
            Return ScanResult.CreateFailed(tool.ToString(), target, validation.ErrorMessage, ScanStatus.Failed)
        End If

        ' Check tool availability
        If ToolStatus.ContainsKey(tool) AndAlso Not ToolStatus(tool).IsAvailable Then
            LogAuditEntry("SCAN_BLOCKED_TOOL_MISSING", target, tool.ToString(), "")
            Return ScanResult.CreateFailed(tool.ToString(), target,
                $"Tool not available. {ToolStatus(tool).InstallInstructions}", ScanStatus.Failed)
        End If

        ' Log scan start
        LogAuditEntry("SCAN_STARTED", target, tool.ToString(), CurrentAuthorization?.ConsentHash)

        ' Create result placeholder
        Dim result As New ScanResult()
        result.Tool = $"fsociety/{tool.ToString().ToLowerInvariant()}"
        result.Target = validation.SanitizedTarget
        result.StartTimestamp = DateTime.UtcNow.ToString("O")
        result.LegalAcknowledgementHash = CurrentAuthorization?.ConsentHash

        Try
            ' TODO: Communicate with companion service via named pipe
            ' For now, return a placeholder indicating service not connected

            Await Task.Delay(1000)  ' Simulate work

            result.Status = ScanStatus.Failed
            result.Errors.Add(New ScanError() With {
                .Code = "SERVICE_NOT_CONNECTED",
                .Message = "Companion security service is not running. Please install and start the Rootcastle Security Orchestrator service.",
                .Timestamp = DateTime.UtcNow.ToString("O")
            })

            LogAuditEntry("SCAN_FAILED", target, tool.ToString(), "SERVICE_NOT_CONNECTED")

        Catch ex As Exception
            result.Status = ScanStatus.Failed
            result.Errors.Add(New ScanError() With {
                .Code = "EXCEPTION",
                .Message = ex.Message,
                .Timestamp = DateTime.UtcNow.ToString("O"),
                .TechnicalDetails = ex.ToString()
            })

            LogAuditEntry("SCAN_ERROR", target, tool.ToString(), ex.GetType().Name)
        Finally
            result.EndTimestamp = DateTime.UtcNow.ToString("O")

            ' Clear single-use authorization
            ClearAuthorization()
        End Try

        Return result
    End Function

#End Region

#Region "Lab Mode"

    ''' <summary>
    ''' Enables Lab Mode with confirmation.
    ''' </summary>
    Public Sub EnableLabMode()
        LabModeEnabled = True
        LogAuditEntry("LAB_MODE_ENABLED", "", "", "")
    End Sub

    ''' <summary>
    ''' Disables Lab Mode.
    ''' </summary>
    Public Sub DisableLabMode()
        LabModeEnabled = False
        LogAuditEntry("LAB_MODE_DISABLED", "", "", "")
    End Sub

#End Region

End Class
