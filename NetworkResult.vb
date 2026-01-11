Option Strict On
Option Explicit On

Imports System

''' <summary>
''' Standardized error taxonomy for all network operations.
''' Maps to specific failure modes for deterministic error handling.
''' </summary>
Public Enum NetworkErrorType
    ''' <summary>No error - operation succeeded</summary>
    None = 0

    ''' <summary>Operation timed out before completion</summary>
    Timeout = 1

    ''' <summary>DNS resolution failed - hostname not found</summary>
    DnsFailure = 2

    ''' <summary>TCP connection refused by target (port closed)</summary>
    TcpRefused = 3

    ''' <summary>TCP target unreachable (network error)</summary>
    TcpUnreachable = 4

    ''' <summary>HTTP request failed with error status code</summary>
    HttpError = 5

    ''' <summary>TLS/SSL handshake or certificate validation failed</summary>
    TlsError = 6

    ''' <summary>Authentication or authorization failed (401/403)</summary>
    Unauthorized = 7

    ''' <summary>Rate limit exceeded (429)</summary>
    RateLimited = 8

    ''' <summary>Invalid configuration provided</summary>
    InvalidConfig = 9

    ''' <summary>Operation was cancelled by user</summary>
    Cancelled = 10

    ''' <summary>Unknown or unclassified error</summary>
    Unknown = 99
End Enum

''' <summary>
''' Target health status derived from probe results.
''' </summary>
Public Enum TargetStatus
    ''' <summary>All probes successful, within normal parameters</summary>
    Healthy = 0

    ''' <summary>Partial success or elevated latency/loss</summary>
    Degraded = 1

    ''' <summary>All probes failed - target unreachable</summary>
    Down = 2

    ''' <summary>Status cannot be determined</summary>
    Unknown = 3
End Enum

''' <summary>
''' Generic result wrapper for network operations.
''' Provides type-safe success/failure handling without exceptions.
''' </summary>
''' <typeparam name="T">The type of the success value</typeparam>
Public Class ProbeResult(Of T)
    ''' <summary>True if operation completed successfully</summary>
    Public Property IsSuccess As Boolean

    ''' <summary>The result value (only valid when IsSuccess = True)</summary>
    Public Property Value As T

    ''' <summary>Target health status derived from this probe</summary>
    Public Property Status As TargetStatus

    ''' <summary>Specific error type (None if successful)</summary>
    Public Property ErrorType As NetworkErrorType

    ''' <summary>User-friendly error message</summary>
    Public Property ErrorMessage As String

    ''' <summary>Technical details for logging (may contain sensitive info)</summary>
    Public Property TechnicalDetails As String

    ''' <summary>Operation duration in milliseconds</summary>
    Public Property DurationMs As Long

    ''' <summary>Correlation ID for tracing</summary>
    Public Property CorrelationId As String

    ''' <summary>Target identifier (IP, hostname, URL)</summary>
    Public Property TargetId As String

    ''' <summary>Timestamp when probe completed</summary>
    Public Property Timestamp As DateTime

    ''' <summary>HTTP status code if applicable</summary>
    Public Property HttpStatusCode As Integer

    ''' <summary>
    ''' Creates a successful result.
    ''' </summary>
    Public Shared Function CreateSuccess(value As T, durationMs As Long, Optional targetId As String = "", Optional correlationId As String = "") As ProbeResult(Of T)
        Return New ProbeResult(Of T) With {
            .IsSuccess = True,
            .Value = value,
            .Status = TargetStatus.Healthy,
            .ErrorType = NetworkErrorType.None,
            .ErrorMessage = "",
            .TechnicalDetails = "",
            .DurationMs = durationMs,
            .TargetId = targetId,
            .CorrelationId = If(String.IsNullOrEmpty(correlationId), Guid.NewGuid().ToString("N").Substring(0, 8), correlationId),
            .Timestamp = DateTime.UtcNow
        }
    End Function

    ''' <summary>
    ''' Creates a failure result with specific error type.
    ''' </summary>
    Public Shared Function CreateFailure(errorType As NetworkErrorType, errorMessage As String, Optional technicalDetails As String = "", Optional durationMs As Long = 0, Optional targetId As String = "", Optional correlationId As String = "") As ProbeResult(Of T)
        Dim status As TargetStatus
        Select Case errorType
            Case NetworkErrorType.Timeout, NetworkErrorType.RateLimited
                status = TargetStatus.Degraded
            Case NetworkErrorType.None
                status = TargetStatus.Healthy
            Case Else
                status = TargetStatus.Down
        End Select

        Return New ProbeResult(Of T) With {
            .IsSuccess = False,
            .Value = Nothing,
            .Status = status,
            .ErrorType = errorType,
            .ErrorMessage = errorMessage,
            .TechnicalDetails = technicalDetails,
            .DurationMs = durationMs,
            .TargetId = targetId,
            .CorrelationId = If(String.IsNullOrEmpty(correlationId), Guid.NewGuid().ToString("N").Substring(0, 8), correlationId),
            .Timestamp = DateTime.UtcNow
        }
    End Function

    ''' <summary>
    ''' Creates a failure from an exception, mapping to appropriate error type.
    ''' </summary>
    Public Shared Function CreateFromException(ex As Exception, Optional durationMs As Long = 0, Optional targetId As String = "", Optional correlationId As String = "") As ProbeResult(Of T)
        Dim errorType As NetworkErrorType
        Dim message As String

        Select Case True
            Case TypeOf ex Is TimeoutException
                errorType = NetworkErrorType.Timeout
                message = "Operation timed out"
            Case TypeOf ex Is OperationCanceledException
                errorType = NetworkErrorType.Cancelled
                message = "Operation was cancelled"
            Case TypeOf ex Is System.Net.Sockets.SocketException
                Dim se = DirectCast(ex, System.Net.Sockets.SocketException)
                Select Case se.SocketErrorCode
                    Case Net.Sockets.SocketError.ConnectionRefused
                        errorType = NetworkErrorType.TcpRefused
                        message = "Connection refused"
                    Case Net.Sockets.SocketError.HostUnreachable, Net.Sockets.SocketError.NetworkUnreachable
                        errorType = NetworkErrorType.TcpUnreachable
                        message = "Host unreachable"
                    Case Net.Sockets.SocketError.TimedOut
                        errorType = NetworkErrorType.Timeout
                        message = "Connection timed out"
                    Case Else
                        errorType = NetworkErrorType.Unknown
                        message = $"Socket error: {se.SocketErrorCode}"
                End Select
            Case TypeOf ex Is System.Net.Http.HttpRequestException
                errorType = NetworkErrorType.HttpError
                message = "HTTP request failed"
            Case Else
                errorType = NetworkErrorType.Unknown
                message = ex.Message
        End Select

        Return CreateFailure(errorType, message, ex.ToString(), durationMs, targetId, correlationId)
    End Function
End Class

''' <summary>
''' Non-generic probe result for operations that don't return a value.
''' </summary>
Public Class ProbeResult
    Inherits ProbeResult(Of Boolean)

    ''' <summary>
    ''' Creates a successful result with no value.
    ''' </summary>
    Public Shared Shadows Function CreateSuccess(durationMs As Long, Optional targetId As String = "", Optional correlationId As String = "") As ProbeResult
        Return New ProbeResult With {
            .IsSuccess = True,
            .Value = True,
            .Status = TargetStatus.Healthy,
            .ErrorType = NetworkErrorType.None,
            .ErrorMessage = "",
            .TechnicalDetails = "",
            .DurationMs = durationMs,
            .TargetId = targetId,
            .CorrelationId = If(String.IsNullOrEmpty(correlationId), Guid.NewGuid().ToString("N").Substring(0, 8), correlationId),
            .Timestamp = DateTime.UtcNow
        }
    End Function
End Class

''' <summary>
''' Structured log entry for observability.
''' </summary>
Public Class LogEntry
    Public Property Timestamp As DateTime
    Public Property Level As String  ' DEBUG, INFO, WARN, ERROR, CRITICAL
    Public Property CorrelationId As String
    Public Property TargetId As String
    Public Property Operation As String
    Public Property DurationMs As Long
    Public Property Outcome As String  ' SUCCESS, FAILURE
    Public Property ErrorCode As NetworkErrorType
    Public Property Message As String

    Public Overrides Function ToString() As String
        Return $"{Timestamp:yyyy-MM-dd HH:mm:ss} [{CorrelationId}] [{Level}] {Operation} -> {Outcome} ({DurationMs}ms) {Message}"
    End Function
End Class
