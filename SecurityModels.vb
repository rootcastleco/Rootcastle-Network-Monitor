Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.Security.Cryptography
Imports System.Text

''' <summary>
''' Security automation models for fsociety module integration.
''' Implements SARIF-compliant output schema and legal compliance tracking.
''' </summary>
''' <remarks>
''' WARNING: These tools are for AUTHORIZED security testing only.
''' Unauthorized scanning is illegal under CFAA, EU Directive on Attacks
''' against Information Systems, and local computer misuse laws.
''' </remarks>

#Region "Enums"

''' <summary>
''' Status of a security scan operation.
''' </summary>
Public Enum ScanStatus
    ''' <summary>Scan is queued but not started</summary>
    Pending = 0
    ''' <summary>Scan is currently executing</summary>
    Running = 1
    ''' <summary>Scan completed successfully</summary>
    Completed = 2
    ''' <summary>Scan failed with error</summary>
    Failed = 3
    ''' <summary>Scan was manually aborted</summary>
    Aborted = 4
    ''' <summary>Scan exceeded timeout limit</summary>
    Timeout = 5
    ''' <summary>Scan blocked due to missing authorization</summary>
    Unauthorized = 6
End Enum

''' <summary>
''' Severity levels for security findings (SARIF-compliant).
''' </summary>
Public Enum FindingSeverity
    ''' <summary>Informational only</summary>
    Info = 0
    ''' <summary>Low risk - consider addressing</summary>
    Low = 1
    ''' <summary>Medium risk - should address</summary>
    Medium = 2
    ''' <summary>High risk - address promptly</summary>
    High = 3
    ''' <summary>Critical risk - address immediately</summary>
    Critical = 4
End Enum

''' <summary>
''' Supported security tools from fsociety framework.
''' </summary>
Public Enum SecurityTool
    ''' <summary>Network exploration and security auditing</summary>
    Nmap = 0
    ''' <summary>SQL injection detection and exploitation</summary>
    SQLMap = 1
    ''' <summary>WordPress vulnerability scanner</summary>
    WPScan = 2
    ''' <summary>Cross-site scripting detection</summary>
    XSStrike = 3
    ''' <summary>DNS enumeration tool</summary>
    DNSRecon = 4
    ''' <summary>Custom user password profiler</summary>
    Cupp = 5
End Enum

''' <summary>
''' Target validation result status.
''' </summary>
Public Enum ValidationStatus
    Valid = 0
    InvalidFormat = 1
    PrivateRange = 2
    ReservedRange = 3
    CommandInjection = 4
    UnsupportedScheme = 5
    TooLong = 6
    Empty = 7
End Enum

#End Region

#Region "Authorization"

''' <summary>
''' Represents explicit user authorization for a security scan.
''' Required before any scan execution for legal compliance.
''' </summary>
Public Class ScanAuthorization
    ''' <summary>Unique authorization ID</summary>
    Public Property AuthorizationId As String

    ''' <summary>When authorization was granted</summary>
    Public Property Timestamp As DateTime

    ''' <summary>SHA256 hash of target (never store actual target)</summary>
    Public Property TargetHash As String

    ''' <summary>User identifier who granted authorization</summary>
    Public Property UserId As String

    ''' <summary>Full text of legal consent acknowledged</summary>
    Public Property ConsentText As String

    ''' <summary>SHA256(ConsentText + Timestamp) for integrity</summary>
    Public Property ConsentHash As String

    ''' <summary>When this authorization expires</summary>
    Public Property ExpiresAt As DateTime

    ''' <summary>Tool authorized for use</summary>
    Public Property AuthorizedTool As SecurityTool

    ''' <summary>Whether lab mode (private IPs allowed) was enabled</summary>
    Public Property LabModeEnabled As Boolean

    ''' <summary>
    ''' Creates a new authorization with computed hashes.
    ''' </summary>
    Public Shared Function Create(target As String, tool As SecurityTool, consentText As String, Optional labMode As Boolean = False, Optional expirationMinutes As Integer = 60) As ScanAuthorization
        Dim auth As New ScanAuthorization()
        auth.AuthorizationId = Guid.NewGuid().ToString("N").ToUpperInvariant()
        auth.Timestamp = DateTime.UtcNow
        auth.TargetHash = ComputeSha256(target)
        auth.UserId = Environment.UserName
        auth.ConsentText = consentText
        auth.ConsentHash = ComputeSha256(consentText & auth.Timestamp.ToString("O"))
        auth.ExpiresAt = auth.Timestamp.AddMinutes(expirationMinutes)
        auth.AuthorizedTool = tool
        auth.LabModeEnabled = labMode
        Return auth
    End Function

    ''' <summary>
    ''' Validates that authorization is still valid.
    ''' </summary>
    Public Function IsValid(targetToCheck As String, toolToCheck As SecurityTool) As Boolean
        If DateTime.UtcNow > ExpiresAt Then Return False
        If ComputeSha256(targetToCheck) <> TargetHash Then Return False
        If toolToCheck <> AuthorizedTool Then Return False
        Return True
    End Function

    Private Shared Function ComputeSha256(input As String) As String
        Using sha As SHA256 = SHA256.Create()
            Dim bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input))
            Return BitConverter.ToString(bytes).Replace("-", "").ToUpperInvariant()
        End Using
    End Function
End Class

#End Region

#Region "Scan Results (SARIF-Compliant)"

''' <summary>
''' SARIF-compliant security scan result.
''' Schema: https://json.schemastore.org/sarif-2.1.0.json
''' </summary>
Public Class ScanResult
    ''' <summary>Tool that performed the scan</summary>
    Public Property Tool As String

    ''' <summary>Tool version</summary>
    Public Property ToolVersion As String

    ''' <summary>Target (sanitized for display only)</summary>
    Public Property Target As String

    ''' <summary>ISO 8601 timestamp of scan start</summary>
    Public Property StartTimestamp As String

    ''' <summary>ISO 8601 timestamp of scan end</summary>
    Public Property EndTimestamp As String

    ''' <summary>Scan completion status</summary>
    Public Property Status As ScanStatus

    ''' <summary>List of security findings</summary>
    Public Property Findings As List(Of Finding)

    ''' <summary>List of errors encountered</summary>
    Public Property Errors As List(Of ScanError)

    ''' <summary>SHA256 hash of authorization consent</summary>
    Public Property LegalAcknowledgementHash As String

    ''' <summary>Scan duration in milliseconds</summary>
    Public Property DurationMs As Long

    ''' <summary>Correlation ID for tracing</summary>
    Public Property CorrelationId As String

    ''' <summary>Raw command executed (sanitized)</summary>
    Public Property CommandSummary As String

    ''' <summary>Exit code from tool</summary>
    Public Property ExitCode As Integer

    Public Sub New()
        Findings = New List(Of Finding)()
        Errors = New List(Of ScanError)()
        CorrelationId = Guid.NewGuid().ToString("N").Substring(0, 12).ToUpperInvariant()
    End Sub

    ''' <summary>
    ''' Creates a failed result with error.
    ''' </summary>
    Public Shared Function CreateFailed(tool As String, target As String, errorMessage As String, status As ScanStatus) As ScanResult
        Dim result As New ScanResult()
        result.Tool = tool
        result.Target = SanitizeForDisplay(target)
        result.StartTimestamp = DateTime.UtcNow.ToString("O")
        result.EndTimestamp = DateTime.UtcNow.ToString("O")
        result.Status = status
        result.Errors.Add(New ScanError() With {
            .Code = status.ToString(),
            .Message = errorMessage,
            .Timestamp = DateTime.UtcNow.ToString("O")
        })
        Return result
    End Function

    Private Shared Function SanitizeForDisplay(input As String) As String
        If String.IsNullOrEmpty(input) Then Return ""
        ' Remove potentially sensitive portions, keep only host
        If input.Contains("@") Then
            input = input.Substring(input.IndexOf("@") + 1)
        End If
        If input.Length > 100 Then input = input.Substring(0, 100) & "..."
        Return input
    End Function
End Class

''' <summary>
''' Individual security finding from a scan.
''' </summary>
Public Class Finding
    ''' <summary>Unique rule/check identifier</summary>
    Public Property RuleId As String

    ''' <summary>Severity level</summary>
    Public Property Severity As FindingSeverity

    ''' <summary>Short title</summary>
    Public Property Title As String

    ''' <summary>Detailed description</summary>
    Public Property Description As String

    ''' <summary>Evidence supporting the finding</summary>
    Public Property Evidence As String

    ''' <summary>How to remediate</summary>
    Public Property Remediation As String

    ''' <summary>Affected URI/location</summary>
    Public Property Location As String

    ''' <summary>CVSS score if applicable</summary>
    Public Property CvssScore As Double

    ''' <summary>CVE reference if applicable</summary>
    Public Property CveId As String
End Class

''' <summary>
''' Error encountered during scan execution.
''' </summary>
Public Class ScanError
    ''' <summary>Error code</summary>
    Public Property Code As String

    ''' <summary>Human-readable message</summary>
    Public Property Message As String

    ''' <summary>When error occurred</summary>
    Public Property Timestamp As String

    ''' <summary>Technical details (not shown to user)</summary>
    Public Property TechnicalDetails As String
End Class

#End Region

#Region "Audit Trail"

''' <summary>
''' Immutable audit log entry with chain integrity.
''' </summary>
Public Class AuditEntry
    ''' <summary>Unique entry ID</summary>
    Public Property EntryId As String

    ''' <summary>Sequence number in chain</summary>
    Public Property SequenceNumber As Long

    ''' <summary>When action occurred</summary>
    Public Property Timestamp As DateTime

    ''' <summary>Action performed</summary>
    Public Property Action As String  ' SCAN_AUTHORIZED, SCAN_STARTED, SCAN_COMPLETED, etc.

    ''' <summary>User who performed action</summary>
    Public Property UserId As String

    ''' <summary>SHA256 hash of target (never actual target)</summary>
    Public Property TargetHash As String

    ''' <summary>Tool used</summary>
    Public Property ToolName As String

    ''' <summary>Authorization hash for this action</summary>
    Public Property AuthorizationHash As String

    ''' <summary>SHA256 of scan result</summary>
    Public Property ResultHash As String

    ''' <summary>SHA256 of previous entry for chain integrity</summary>
    Public Property PreviousEntryHash As String

    ''' <summary>SHA256 of this entry</summary>
    Public Property EntryHash As String

    ''' <summary>
    ''' Computes the hash of this entry for chain integrity.
    ''' </summary>
    Public Function ComputeHash() As String
        Dim data = $"{EntryId}|{SequenceNumber}|{Timestamp:O}|{Action}|{UserId}|{TargetHash}|{ToolName}|{AuthorizationHash}|{ResultHash}|{PreviousEntryHash}"
        Using sha As SHA256 = SHA256.Create()
            Dim bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(data))
            Return BitConverter.ToString(bytes).Replace("-", "").ToUpperInvariant()
        End Using
    End Function
End Class

#End Region

#Region "Tool Configuration"

''' <summary>
''' Configuration for a security tool execution.
''' </summary>
Public Class ToolConfiguration
    ''' <summary>Tool to execute</summary>
    Public Property Tool As SecurityTool

    ''' <summary>Timeout in seconds</summary>
    Public Property TimeoutSeconds As Integer

    ''' <summary>Maximum memory in MB</summary>
    Public Property MaxMemoryMb As Integer

    ''' <summary>Additional arguments (validated)</summary>
    Public Property Arguments As List(Of String)

    ''' <summary>Output format preference</summary>
    Public Property OutputFormat As String

    Public Sub New()
        Arguments = New List(Of String)()
        TimeoutSeconds = 300  ' 5 minutes default
        MaxMemoryMb = 512
        OutputFormat = "xml"
    End Sub

    ''' <summary>
    ''' Returns default configuration for a tool.
    ''' </summary>
    Public Shared Function GetDefault(tool As SecurityTool) As ToolConfiguration
        Dim config As New ToolConfiguration()
        config.Tool = tool

        Select Case tool
            Case SecurityTool.Nmap
                config.TimeoutSeconds = 300
                config.OutputFormat = "xml"
            Case SecurityTool.SQLMap
                config.TimeoutSeconds = 600
                config.MaxMemoryMb = 1024
            Case SecurityTool.WPScan
                config.TimeoutSeconds = 300
            Case SecurityTool.DNSRecon
                config.TimeoutSeconds = 120
            Case Else
                config.TimeoutSeconds = 300
        End Select

        Return config
    End Function
End Class

#End Region

#Region "Legal Constants"

''' <summary>
''' Legal compliance constants and disclaimer text.
''' </summary>
Public Class LegalCompliance
    Public Const DISCLAIMER_TEXT As String = "WARNING: Unauthorized scanning or testing of networks, systems, or applications is ILLEGAL and may result in criminal prosecution under applicable laws including the Computer Fraud and Abuse Act (CFAA), EU Directive on Attacks against Information Systems, and local computer misuse laws. By proceeding, you confirm that you own the target system or possess explicit written permission from the legal owner. Rootcastle Engineering & Innovation assumes NO LIABILITY for misuse of these tools."

    Public Const CONSENT_CHECKBOX_TEXT As String = "I confirm that I own or have explicit written authorization to scan the specified target. I understand that unauthorized scanning is illegal and I accept full responsibility for my actions."

    Public Const MIT_LICENSE_NOTICE As String = "This integration uses components from the fsociety framework, distributed under the MIT License. See https://github.com/Manisso/fsociety for license details."

    ''' <summary>
    ''' Generates consent text with timestamp for hashing.
    ''' </summary>
    Public Shared Function GenerateConsentText(target As String, tool As SecurityTool) As String
        Return $"I authorize scanning of [{target}] using [{tool}] at [{DateTime.UtcNow:O}]. {CONSENT_CHECKBOX_TEXT}"
    End Function
End Class

#End Region
