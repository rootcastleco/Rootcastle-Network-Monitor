Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.Net
Imports System.Text.RegularExpressions

''' <summary>
''' RFC-compliant target validation with Lab Mode support.
''' Validates IP addresses, domains, and URLs using allowlist-based parsing.
''' </summary>
''' <remarks>
''' Lab Mode allows scanning of private RFC 1918 ranges for internal testing.
''' Public internet egress is blocked in Lab Mode unless explicitly confirmed.
''' </remarks>
Public Class TargetValidator

#Region "Constants"

    ' RFC 1918 Private Ranges
    Private Shared ReadOnly PRIVATE_RANGES As String() = {
        "10.0.0.0/8",      ' Class A
        "172.16.0.0/12",   ' Class B  
        "192.168.0.0/16"   ' Class C
    }

    ' Reserved/Special Ranges (never allow)
    Private Shared ReadOnly RESERVED_RANGES As String() = {
        "0.0.0.0/8",       ' This network
        "127.0.0.0/8",     ' Loopback
        "169.254.0.0/16",  ' Link-local
        "224.0.0.0/4",     ' Multicast
        "240.0.0.0/4",     ' Reserved
        "255.255.255.255/32" ' Broadcast
    }

    ' Dangerous characters for command injection
    Private Shared ReadOnly INJECTION_CHARS As Char() = {
        ";"c, "|"c, "&"c, "$"c, "`"c, "("c, ")"c, "{"c, "}"c,
        "["c, "]"c, "<"c, ">"c, "!"c, "\"c, "'"c, """"c, vbLf(0), vbCr(0)
    }

    Private Const MAX_TARGET_LENGTH As Integer = 253  ' RFC 1035 max domain length
    Private Const MAX_URL_LENGTH As Integer = 2048

#End Region

#Region "Validation Results"

    ''' <summary>
    ''' Result of target validation.
    ''' </summary>
    Public Class ValidationResult
        Public Property IsValid As Boolean
        Public Property Status As ValidationStatus
        Public Property SanitizedTarget As String
        Public Property ErrorMessage As String
        Public Property IsPrivateRange As Boolean
        Public Property RequiresLabMode As Boolean

        Public Shared Function Success(sanitized As String, Optional isPrivate As Boolean = False) As ValidationResult
            Return New ValidationResult() With {
                .IsValid = True,
                .Status = ValidationStatus.Valid,
                .SanitizedTarget = sanitized,
                .IsPrivateRange = isPrivate,
                .RequiresLabMode = isPrivate
            }
        End Function

        Public Shared Function Failure(status As ValidationStatus, message As String) As ValidationResult
            Return New ValidationResult() With {
                .IsValid = False,
                .Status = status,
                .ErrorMessage = message
            }
        End Function
    End Class

#End Region

#Region "IPv4 Validation"

    ''' <summary>
    ''' Validates IPv4 address. Rejects private ranges unless Lab Mode enabled.
    ''' </summary>
    ''' <param name="input">IP address string</param>
    ''' <param name="labModeEnabled">Allow private RFC 1918 ranges</param>
    Public Shared Function ValidateIPv4(input As String, labModeEnabled As Boolean) As ValidationResult
        ' Empty check
        If String.IsNullOrWhiteSpace(input) Then
            Return ValidationResult.Failure(ValidationStatus.Empty, "Target cannot be empty")
        End If

        ' Length check
        If input.Length > MAX_TARGET_LENGTH Then
            Return ValidationResult.Failure(ValidationStatus.TooLong, $"Target exceeds maximum length of {MAX_TARGET_LENGTH}")
        End If

        ' Trim and sanitize
        Dim sanitized = input.Trim()

        ' Command injection check
        If ContainsInjectionChars(sanitized) Then
            Return ValidationResult.Failure(ValidationStatus.CommandInjection, "Target contains invalid characters")
        End If

        ' Parse IP address
        Dim ipAddress As IPAddress = Nothing
        If Not IPAddress.TryParse(sanitized, ipAddress) Then
            Return ValidationResult.Failure(ValidationStatus.InvalidFormat, "Invalid IPv4 address format")
        End If

        ' Must be IPv4
        If ipAddress.AddressFamily <> System.Net.Sockets.AddressFamily.InterNetwork Then
            Return ValidationResult.Failure(ValidationStatus.InvalidFormat, "Only IPv4 addresses are supported")
        End If

        ' Check reserved ranges (always blocked)
        If IsReservedRange(ipAddress) Then
            Return ValidationResult.Failure(ValidationStatus.ReservedRange, "Reserved IP ranges are not allowed (loopback, multicast, etc.)")
        End If

        ' Check private ranges
        Dim isPrivate = IsPrivateRange(ipAddress)
        If isPrivate AndAlso Not labModeEnabled Then
            Return ValidationResult.Failure(ValidationStatus.PrivateRange,
                "Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x) require Lab Mode to be enabled")
        End If

        Return ValidationResult.Success(sanitized, isPrivate)
    End Function

    ''' <summary>
    ''' Checks if IP is in RFC 1918 private range.
    ''' </summary>
    Private Shared Function IsPrivateRange(ip As IPAddress) As Boolean
        Dim bytes = ip.GetAddressBytes()
        If bytes.Length <> 4 Then Return False

        ' 10.0.0.0/8
        If bytes(0) = 10 Then Return True

        ' 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
        If bytes(0) = 172 AndAlso bytes(1) >= 16 AndAlso bytes(1) <= 31 Then Return True

        ' 192.168.0.0/16
        If bytes(0) = 192 AndAlso bytes(1) = 168 Then Return True

        Return False
    End Function

    ''' <summary>
    ''' Checks if IP is in reserved/special-use range.
    ''' </summary>
    Private Shared Function IsReservedRange(ip As IPAddress) As Boolean
        Dim bytes = ip.GetAddressBytes()
        If bytes.Length <> 4 Then Return False

        ' 0.0.0.0/8
        If bytes(0) = 0 Then Return True

        ' 127.0.0.0/8 (loopback)
        If bytes(0) = 127 Then Return True

        ' 169.254.0.0/16 (link-local)
        If bytes(0) = 169 AndAlso bytes(1) = 254 Then Return True

        ' 224.0.0.0/4 (multicast)
        If bytes(0) >= 224 AndAlso bytes(0) <= 239 Then Return True

        ' 240.0.0.0/4 (reserved)
        If bytes(0) >= 240 Then Return True

        Return False
    End Function

#End Region

#Region "Domain Validation"

    ''' <summary>
    ''' Validates domain name per RFC 1035.
    ''' </summary>
    Public Shared Function ValidateDomain(input As String, labModeEnabled As Boolean) As ValidationResult
        ' Empty check
        If String.IsNullOrWhiteSpace(input) Then
            Return ValidationResult.Failure(ValidationStatus.Empty, "Domain cannot be empty")
        End If

        ' Length check
        If input.Length > MAX_TARGET_LENGTH Then
            Return ValidationResult.Failure(ValidationStatus.TooLong, $"Domain exceeds maximum length of {MAX_TARGET_LENGTH}")
        End If

        ' Trim and lowercase
        Dim sanitized = input.Trim().ToLowerInvariant()

        ' Command injection check
        If ContainsInjectionChars(sanitized) Then
            Return ValidationResult.Failure(ValidationStatus.CommandInjection, "Domain contains invalid characters")
        End If

        ' RFC 1035 domain pattern
        ' Labels: alphanumeric, hyphens (not at start/end), 1-63 chars each
        ' Total: 1-253 chars
        Dim domainPattern = "^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
        If Not Regex.IsMatch(sanitized, domainPattern) Then
            Return ValidationResult.Failure(ValidationStatus.InvalidFormat, "Invalid domain name format")
        End If

        ' Check for localhost variants
        If sanitized = "localhost" OrElse sanitized.EndsWith(".localhost") OrElse sanitized.EndsWith(".local") Then
            If Not labModeEnabled Then
                Return ValidationResult.Failure(ValidationStatus.PrivateRange, "localhost domains require Lab Mode")
            End If
            Return ValidationResult.Success(sanitized, True)
        End If

        Return ValidationResult.Success(sanitized, False)
    End Function

#End Region

#Region "URL Validation"

    ''' <summary>
    ''' Validates URL with scheme enforcement (http/https only).
    ''' </summary>
    Public Shared Function ValidateUrl(input As String, labModeEnabled As Boolean) As ValidationResult
        ' Empty check
        If String.IsNullOrWhiteSpace(input) Then
            Return ValidationResult.Failure(ValidationStatus.Empty, "URL cannot be empty")
        End If

        ' Length check
        If input.Length > MAX_URL_LENGTH Then
            Return ValidationResult.Failure(ValidationStatus.TooLong, $"URL exceeds maximum length of {MAX_URL_LENGTH}")
        End If

        ' Trim
        Dim sanitized = input.Trim()

        ' Command injection check
        If ContainsInjectionChars(sanitized) Then
            Return ValidationResult.Failure(ValidationStatus.CommandInjection, "URL contains invalid characters")
        End If

        ' Parse URL
        Dim uri As Uri = Nothing
        If Not Uri.TryCreate(sanitized, UriKind.Absolute, uri) Then
            Return ValidationResult.Failure(ValidationStatus.InvalidFormat, "Invalid URL format")
        End If

        ' Scheme enforcement (http/https only)
        If uri.Scheme <> "http" AndAlso uri.Scheme <> "https" Then
            Return ValidationResult.Failure(ValidationStatus.UnsupportedScheme, "Only http:// and https:// schemes are allowed")
        End If

        ' Validate host portion
        Dim hostResult As ValidationResult

        ' Check if host is IP or domain
        Dim hostIp As IPAddress = Nothing
        If IPAddress.TryParse(uri.Host, hostIp) Then
            hostResult = ValidateIPv4(uri.Host, labModeEnabled)
        Else
            hostResult = ValidateDomain(uri.Host, labModeEnabled)
        End If

        If Not hostResult.IsValid Then
            Return hostResult
        End If

        ' Reconstruct sanitized URL
        Dim sanitizedUrl = $"{uri.Scheme}://{uri.Host}"
        If uri.Port <> 80 AndAlso uri.Port <> 443 Then
            sanitizedUrl &= $":{uri.Port}"
        End If
        sanitizedUrl &= uri.PathAndQuery

        Return ValidationResult.Success(sanitizedUrl, hostResult.IsPrivateRange)
    End Function

#End Region

#Region "CIDR Range Validation"

    ''' <summary>
    ''' Validates CIDR range notation for network scanning.
    ''' </summary>
    Public Shared Function ValidateCidrRange(input As String, labModeEnabled As Boolean) As ValidationResult
        ' Empty check
        If String.IsNullOrWhiteSpace(input) Then
            Return ValidationResult.Failure(ValidationStatus.Empty, "CIDR range cannot be empty")
        End If

        ' Trim
        Dim sanitized = input.Trim()

        ' Command injection check
        If ContainsInjectionChars(sanitized) Then
            Return ValidationResult.Failure(ValidationStatus.CommandInjection, "CIDR contains invalid characters")
        End If

        ' Parse CIDR
        Dim parts = sanitized.Split("/"c)
        If parts.Length <> 2 Then
            Return ValidationResult.Failure(ValidationStatus.InvalidFormat, "Invalid CIDR format (expected x.x.x.x/prefix)")
        End If

        ' Validate IP portion
        Dim ipResult = ValidateIPv4(parts(0), labModeEnabled)
        If Not ipResult.IsValid Then
            Return ipResult
        End If

        ' Validate prefix
        Dim prefix As Integer
        If Not Integer.TryParse(parts(1), prefix) OrElse prefix < 0 OrElse prefix > 32 Then
            Return ValidationResult.Failure(ValidationStatus.InvalidFormat, "CIDR prefix must be 0-32")
        End If

        ' Limit scan range (prevent /8 or /16 on public internet)
        If Not ipResult.IsPrivateRange AndAlso prefix < 24 Then
            Return ValidationResult.Failure(ValidationStatus.InvalidFormat,
                "Public IP ranges smaller than /24 are not allowed (too many hosts)")
        End If

        Return ValidationResult.Success(sanitized, ipResult.IsPrivateRange)
    End Function

#End Region

#Region "Helpers"

    ''' <summary>
    ''' Checks for command injection characters.
    ''' </summary>
    Private Shared Function ContainsInjectionChars(input As String) As Boolean
        For Each c In INJECTION_CHARS
            If input.Contains(c) Then Return True
        Next
        Return False
    End Function

    ''' <summary>
    ''' Sanitizes input by removing dangerous characters.
    ''' </summary>
    Public Shared Function SanitizeInput(input As String) As String
        If String.IsNullOrEmpty(input) Then Return ""

        Dim result = input.Trim()

        ' Remove injection characters
        For Each c In INJECTION_CHARS
            result = result.Replace(c.ToString(), "")
        Next

        ' Limit length
        If result.Length > MAX_TARGET_LENGTH Then
            result = result.Substring(0, MAX_TARGET_LENGTH)
        End If

        Return result
    End Function

    ''' <summary>
    ''' Determines the best validation method based on input format.
    ''' </summary>
    Public Shared Function AutoValidate(input As String, labModeEnabled As Boolean) As ValidationResult
        If String.IsNullOrWhiteSpace(input) Then
            Return ValidationResult.Failure(ValidationStatus.Empty, "Target cannot be empty")
        End If

        Dim trimmed = input.Trim()

        ' Check if it's a URL
        If trimmed.StartsWith("http://") OrElse trimmed.StartsWith("https://") Then
            Return ValidateUrl(trimmed, labModeEnabled)
        End If

        ' Check if it's a CIDR range
        If trimmed.Contains("/") Then
            Return ValidateCidrRange(trimmed, labModeEnabled)
        End If

        ' Check if it's an IP address
        Dim ipAddress As IPAddress = Nothing
        If IPAddress.TryParse(trimmed, ipAddress) Then
            Return ValidateIPv4(trimmed, labModeEnabled)
        End If

        ' Assume it's a domain
        Return ValidateDomain(trimmed, labModeEnabled)
    End Function

#End Region

End Class
