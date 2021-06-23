function Invoke-AnalyzeServer {
    <#
.SYNOPSIS
    Get the Qualys SSL Labs API Status
.DESCRIPTION
    Get the Qualys SSL Labs API Status, this should be used to check the availability of the SSL Labs servers, retrieve the engine and criteria version, and initialize the maximum number of concurrent assessments. Returns one Info object on success.
.PARAMETER AcceptTaC
    Accept the terms and conditions: https://www.ssllabs.com/about/terms.html
.EXAMPLE
    Get-SSLLabsStatus
.EXAMPLE
    Get-SSLLabsStatus -AcceptTaC
.NOTES
    Function Name : Invoke-AuroraAddRecord
    Version       : v2021.0609.0830
    Author        : John Billekens
    Api Info      : https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
    Requires      : Internet
.LINK
    https://github.com/j81blog/J81.SSLLabs
#> 
    [OutputType('Qualys.SSLLabs.SSLTest.Object')]    
    [CmdletBinding(DefaultParameterSetName = 'Summary')]
    param(
        [Parameter(ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'Summary')]
        [parameter(ValueFromPipeline)]    
        [Alias('Host', 'DNSName')]
        [string[]]$Hostname,

        [Parameter(ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'Summary')]
        [Alias('Publish')]    
        [Switch]$PublishReport,

        [Parameter(ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'Summary')]
        [Alias('New')]
        [Switch]$StartNew,

        [Parameter(ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'Summary')]
        [Alias('Cache')]
        [Switch]$FromCache,

        [Parameter(ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'Summary')]
        [Alias('Age')]
        [Int]$MaxAge,

        [Parameter(ParameterSetName = 'All')]
        [Switch]$All,

        [Parameter(ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'Summary')]
        [Alias('Accept')]    
        [Switch]$AcceptTaC,

        [Parameter(ParameterSetName = 'All')]
        [Parameter(ParameterSetName = 'Summary')]
        [Switch]$IgnoreMismatch,

        [Parameter(ParameterSetName = 'Summary')]
        [Switch]$Summary
    )
    Begin {
        Write-Verbose "[Invoke-AnalyzeServer] Initializing"
        $ParentProgress = 10
        $ProgressParams = @{
            Id               = 1
            PercentComplete  = $ParentProgress
            Activity         = "Analyzing Server(s)"
            CurrentOperation = "Initializing"
        }
        Write-Progress @ProgressParams
        $ApiUrl = "https://api.ssllabs.com/api/v3"
        $ApiUrn = "analyze"
        $ApiUri = '{0}/{1}' -f $ApiUrl, $ApiUrn
        $DefaultArguments = @{
            Uri    = $ApiUri
            Method = 'GET'
        }
        if ('UseBasicParsing' -in (Get-Command Invoke-RestMethod).Parameters.Keys) {
            $DefaultArguments.UseBasicParsing = $true
        }
        $SSLChecks = @([PSCustomObject]@{ })
        $finalReports = @([PSCustomObject]@{ PSTypeName = 'Qualys.SSLLabs.SSLTest.Object' })
    }

    Process {
        Write-Verbose "[Invoke-AnalyzeServer] Processing new reports"
        <#
            * host - hostname; required.
            * publish - set to "on" if assessment results should be published on the public results boards; optional, defaults to "off".
            * startNew - if set to "on" then cached assessment results are ignored and a new assessment is started. However, if there's already an assessment in progress, its status is delivered instead. This parameter should be used only once to initiate a new assessment; further invocations should omit it to avoid causing an assessment loop.
            * fromCache - always deliver cached assessment reports if available; optional, defaults to "off". This parameter is intended for API consumers that don't want to wait for assessment results. Can't be used at the same time as the startNew parameter.
            * maxAge - maximum report age, in hours, if retrieving from cache (fromCache parameter set).
            * all - by default this call results only summaries of individual endpoints. If this parameter is set to "on", full information will be returned. If set to "done", full information will be returned only if the assessment is complete (status is READY or ERROR).
            * ignoreMismatch - set to "on" to proceed with assessments even when the server certificate doesn't match the assessment hostname. Set to off by default. Please note that this parameter is ignored if a cached report is returned.
        #>
        $pCount = 0
        ForEach ($name in $Hostname) {
            $pCount++
            $ParentProgress += (10 / $Hostname.Count)

            $ProgressParams = @{
                Id               = 1
                PercentComplete  = $ParentProgress
                Activity         = "Analyzing Server(s)"
                Status           = "Processing new reports"
                CurrentOperation = "Requesting test for $name"
            }
            Write-Progress @ProgressParams
            Write-Debug "Requesting new reports, hostname: $name"
            $apiInfo = Get-SSLLabsStatus -AcceptTaC:$AcceptTaC
            $AcceptTaC = $true
            $parameters = @{ }
            $parameters.host = $name
            if ($PublishReport) { $parameters.publish = 'on' } else { $parameters.publish = 'off' }
            if ($PSBoundParameters.ContainsKey('MaxAge')) { $parameters.maxAge = $MaxAge }
            if ($PSBoundParameters.ContainsKey('IgnoreMismatch')) { $parameters.ignoreMismatch = $IgnoreMismatch }
            if ($FromCache) { $parameters.fromCache = 'on' } 
            if ($StartNew) { $parameters.startNew = 'on' } 
            if ($All) { $parameters.all = 'done' }
            $SSLCheck = [PSCustomObject]@{
                Hostname  = $name
                Arguments = $DefaultArguments.Clone()
                Result    = $null
                IsFailed  = $false
                IsReady   = $false
                NextPoll  = (Get-Date)
                EndPoints = 1
            }
            $SSLCheck.Arguments.Uri = New-HttpQuery -Uri $ApiUri -Parameters $parameters
            Write-Debug "[$($apiInfo.currentAssessments)/$($apiInfo.maxAssessments)] Uri: $($SSLCheck.Arguments.Uri)"
            try {
                if ($apiInfo.IsReady) {
                    if ($SSLChecks.Count -gt 1) {
                        Write-Debug "Start waiting for next attempt: $($apiInfo.newAssessmentCoolOff) Milliseconds"
                        Start-Sleep -Milliseconds $apiInfo.newAssessmentCoolOff
                    }
                    $Arguments = $SSLCheck.Arguments.Clone()
                    $SSLCheck.result = Invoke-RestMethod @Arguments -Verbose:$false
                    $SSLCheck.NextPoll = (Get-Date).AddSeconds(10)
                    if ($StartNew) { $parameters.startNew = 'off' }
                    $SSLCheck.Arguments.Uri = New-HttpQuery -Uri $ApiUri -Parameters $parameters
                    #status - assessment status; possible values: DNS, ERROR, IN_PROGRESS, and READY.
                } elseif ($apiInfo.currentAssessments -ge $apiInfo.maxAssessments) {
                    Write-Warning -Message "Cannot process `"$name`" at the moment, max assessments ($($SSLCheck.result.currentAssessments)/$($SSLCheck.result.maxAssessments)) reached"
                    $SSLCheck.IsFailed = $true
                } else {
                    Write-Warning -Message "Cannot process `"$name`" at the moment, unknown issue!"
                    $SSLCheck.IsFailed = $true
                }
            } catch {
                Write-Error "Error while requesting SSL Check, $($_.Exception.Message)"
                $SSLCheck.IsFailed = $true
            }
            if ($SSLCheck.IsFailed) {
                $report = [PSCustomObject]@{
                    PSTypeName = 'Qualys.SSLLabs.SSLTest.Object'
                    Hostname   = $name
                    IPAddress  = $null
                    Grade      = $null
                    Status     = "Failed"
                    Result     = $Null
                }
                Write-Debug ($report | Select-Object -Property Hostname, IPAddress, Grade, Status | ConvertTo-Json -Compress)
                $finalReports += $report
            }
            $SSLChecks += $SSLCheck
        }
        $ParentProgress = 20
    }
    End {
        Write-Verbose "[Invoke-AnalyzeServer] Waiting for reports to be ready"
        [IPAddress]$ipRef = $null
        $progressPart = 80 / $SSLChecks.Count
        $checks = $SSLChecks | Where-Object { $_.IsReady -eq $false -and $_.IsFailed -eq $false }
        try { $ParentProgress += $progressPart * ($SSLChecks.Count - $checks.Count) } catch { }
        while ($checks.Count -ne 0) {
            $ProgressParams = @{
                Id               = 1
                PercentComplete  = $ParentProgress
                Activity         = "Analyzing Server(s)"
                Status           = "Waiting for reports to be ready"
                CurrentOperation = "Waiting"

            }
            Write-Progress @ProgressParams
            foreach ($check in $checks) {
                $check.EndPoints = try { [Int]::Parse($check.result.endpoints.count) } catch { 1 }
                if ((Get-Date) -ge $check.NextPoll) {
                    try {
                        $Arguments = $check.Arguments.Clone()
                        $check.result = Invoke-RestMethod @Arguments -Verbose:$false
                        $check.NextPoll = (Get-Date).AddSeconds(10)
                        Write-Debug "Uri:$($Arguments.Uri) => Status:$($check.result.status)"
                        switch ($check.result.status) {
                            'DNS' {
                                Continue
                            }
                            'ERROR' {
                                $check.IsFailed = $true
                                $report = [PSCustomObject]@{
                                    PSTypeName = 'Qualys.SSLLabs.SSLTest.Object'
                                    Hostname   = $check.Hostname
                                    IPAddress  = $null
                                    Grade      = $null
                                    Status     = "ERROR"
                                    Result     = [PSCustomObject]@{ ErrorMessage = $($check.result.errors.message) }
                                }
                                Write-Debug ($report | Select-Object -Property Hostname, IPAddress, Grade, Status | ConvertTo-Json -Compress)
                                $finalReports += $report
                                $ParentProgress += $progressPart
                                Write-Error "Error while analyzing, $($check.result.errors.message)"
                                Continue
                            }
                            'IN_PROGRESS' {
                                For ($count = 0; $count -le $check.result.endpoints.count - 1; $count++) {
                                    $endpoint = $check.result.endpoints[$count]
                                    $progressCheck = try { [Int]$endpoint.progress } catch { 0 }
                                    if ($endpoint.statusMessage -like "In progress") {
                                        $eta = try { [int]::Parse($check.result.endpoints[$count].eta) } catch { $secToAdd }
                                        Write-Debug "[$count/$($check.result.endpoints.count)] $($progressCheck)%, ETA:$($eta)s"
                                        $NextPollTime = try { (Get-Date).AddSeconds($eta) } catch { (Get-Date).AddSeconds($secToAdd) }
                                        if ($NextPollTime -gt $check.NextPoll) {
                                            $check.NextPoll = $NextPollTime
                                        }
                                    }
                                    try {
                                        $ProgressParams.CurrentOperation = "Progress ($count/$($check.result.endpoints.count)) $($check.result.host) - $($endpoint.ipAddress)  -$($progressCheck)%"
                                        $ProgressParams.PercentComplete = $ParentProgress
                                        Write-Progress @ProgressParams
                                    } catch { }
                                    #Write-Debug "$($check.result | ConvertTo-Json)"
                                }
                                Continue
                            }
                            'READY' {
                                $ApiUrn = "getEndpointData"
                                $ApiUri = '{0}/{1}' -f $ApiUrl, $ApiUrn
                                $Arguments = $DefaultArguments.Clone()
                                For ($count = 0; $count -le $check.result.endpoints.count - 1; $count++) {
                                    if ([IPAddress]::TryParse($check.result.endpoints[$count].ipAddress, [ref]$ipRef)) {
                                        $parameters = @{ }
                                        $parameters.host = $check.result.host
                                        $parameters.s = $check.result.endpoints[$count].ipAddress
                                        $Arguments.Uri = New-HttpQuery -Uri $ApiUri -Parameters $parameters
                                        try {
                                            Write-Debug "Uri: $($Arguments.Uri)"
                                            $response = Invoke-RestMethod @Arguments -Verbose:$false
                                            $report = [PSCustomObject]@{
                                                Hostname  = $check.Hostname
                                                IPAddress = $response.ipAddress
                                                Grade     = $response.grade
                                                Status    = $response.statusMessage
                                                Result    = $response
                                            }
                                            Write-Debug "Result: $($report | Select-Object -Property Hostname, IPAddress, Grade, Status | ConvertTo-Json -Compress)"
                                            $finalReports += $report
                                        } catch {
                                            $check.IsFailed = $true
                                            Write-Error "Error while getting the report, $($check.result.errors.message)"
                                        }
                                    }
                                }
                                $check.IsReady = $true
                                $ParentProgress += $progressPart
                                Continue
                            }
                            Default {
                                Write-Warning "Unknown status: `"$($check | ConvertTo-Json)`""
                                $report = [PSCustomObject]@{
                                    Hostname  = $check.Hostname
                                    IPAddress = $null
                                    Grade     = $null
                                    Status    = "Failed - Unknown"
                                    Result    = $check.result
                                }
                                $finalReports += $report
                                $check.IsFailed = $true
                                $ParentProgress += $progressPart
                                Continue
                            }
                        }    
                    } catch {
                        Write-Error "Caught an error, $($_.Exception.Message)"
                        $report = [PSCustomObject]@{
                            Hostname  = $check.Hostname
                            IPAddress = $null
                            Grade     = $null
                            Status    = "Error - $($_.Exception.Message)"
                            Result    = $check.result
                        }
                        $finalReports += $report
                        $ParentProgress += $progressPart
                        $check.IsFailed = $true
                    }
                }
                $ProgressParams.PercentComplete = $ParentProgress
                $ProgressParams.CurrentOperation = "Waiting"
                Write-Progress @ProgressParams
            }
            $Checks = @()
            $Checks += $SSLChecks | Where-Object { $_.IsReady -eq $false -and $_.IsFailed -eq $false }
            if ($Checks.Count -gt 0 ) {
                Start-Sleep -Seconds 1
            }
        }
        $ProgressParams.PercentComplete = 100
        $ProgressParams.CurrentOperation = "Finalizing"
        $ProgressParams.Completed = $true
        Write-Progress @ProgressParams
        if ($Summary) {
            Write-Output ($finalReports | Select-Object -Property Hostname, IPAddress, Grade, Status)
        } else {
            Write-Output $finalReports
        }
        Write-Verbose "[Invoke-AnalyzeServer] Finished"
    }
}

# SIG # Begin signature block
# MIITYgYJKoZIhvcNAQcCoIITUzCCE08CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDiTA9Fk+hc0G9g
# TDjktgc7rpSdHLQddDGuiJSqOEqWbqCCEHUwggTzMIID26ADAgECAhAsJ03zZBC0
# i/247uUvWN5TMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoT
# D1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29kZSBTaWdu
# aW5nIENBMB4XDTIxMDUwNTAwMDAwMFoXDTI0MDUwNDIzNTk1OVowWzELMAkGA1UE
# BhMCTkwxEjAQBgNVBAcMCVZlbGRob3ZlbjEbMBkGA1UECgwSSm9oYW5uZXMgQmls
# bGVrZW5zMRswGQYDVQQDDBJKb2hhbm5lcyBCaWxsZWtlbnMwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCsfgRG81keOHalHfCUgxOa1Qy4VNOnGxB8SL8e
# rjP9SfcF13McP7F1HGka5Be495pTZ+duGbaQMNozwg/5Dg9IRJEeBabeSSJJCbZo
# SNpmUu7NNRRfidQxlPC81LxTVHxJ7In0MEfCVm7rWcri28MRCAuafqOfSE+hyb1Z
# /tKyCyQ5RUq3kjs/CF+VfMHsJn6ZT63YqewRkwHuc7UogTTZKjhPJ9prGLTer8UX
# UgvsGRbvhYZXIEuy+bmx/iJ1yRl1kX4nj6gUYzlhemOnlSDD66YOrkLDhXPMXLym
# AN7h0/W5Bo//R5itgvdGBkXkWCKRASnq/9PTcoxW6mwtgU8xAgMBAAGjggGQMIIB
# jDAfBgNVHSMEGDAWgBQO4TqoUzox1Yq+wbutZxoDha00DjAdBgNVHQ4EFgQUZWMy
# gC0i1u2NZ1msk2Mm5nJm5AswDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQDAgQQMEoGA1UdIARD
# MEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGln
# by5jb20vQ1BTMAgGBmeBDAEEATBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3Js
# LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2RlU2lnbmluZ0NBLmNybDBzBggrBgEF
# BQcBAQRnMGUwPgYIKwYBBQUHMAKGMmh0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2Vj
# dGlnb1JTQUNvZGVTaWduaW5nQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2Nz
# cC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEARjv9ieRocb1DXRWm3XtY
# jjuSRjlvkoPd9wS6DNfsGlSU42BFd9LCKSyRREZVu8FDq7dN0PhD4bBTT+k6AgrY
# KG6f/8yUponOdxskv850SjN2S2FeVuR20pqActMrpd1+GCylG8mj8RGjdrLQ3QuX
# qYKS68WJ39WWYdVB/8Ftajir5p6sAfwHErLhbJS6WwmYjGI/9SekossvU8mZjZwo
# Gbu+fjZhPc4PhjbEh0ABSsPMfGjQQsg5zLFjg/P+cS6hgYI7qctToo0TexGe32DY
# fFWHrHuBErW2qXEJvzSqM5OtLRD06a4lH5ZkhojhMOX9S8xDs/ArDKgX1j1Xm4Tu
# DjCCBYEwggRpoAMCAQICEDlyRDr5IrdR19NsEN0xNZUwDQYJKoZIhvcNAQEMBQAw
# ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
# A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
# BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0xOTAzMTIwMDAwMDBaFw0y
# ODEyMzEyMzU5NTlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNl
# eTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1Qg
# TmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1
# dGhvcml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIASZRc2DsPb
# CLPQrFcNdu3NJ9NMrVCDYeKqIE0JLWQJ3M6Jn8w9qez2z8Hc8dOx1ns3KBErR9o5
# xrw6GbRfpr19naNjQrZ28qk7K5H44m/Q7BYgkAk+4uh0yRi0kdRiZNt/owbxiBhq
# kCI8vP4T8IcUe/bkH47U5FHGEWdGCFHLhhRUP7wz/n5snP8WnRi9UY41pqdmyHJn
# 2yFmsdSbeAPAUDrozPDcvJ5M/q8FljUfV1q3/875PbcstvZU3cjnEjpNrkyKt1ya
# tLcgPcp/IjSufjtoZgFE5wFORlObM2D3lL5TN5BzQ/Myw1Pv26r+dE5px2uMYJPe
# xMcM3+EyrsyTO1F4lWeL7j1W/gzQaQ8bD/MlJmszbfduR/pzQ+V+DqVmsSl8MoRj
# VYnEDcGTVDAZE6zTfTen6106bDVc20HXEtqpSQvf2ICKCZNijrVmzyWIzYS4sT+k
# OQ/ZAp7rEkyVfPNrBaleFoPMuGfi6BOdzFuC00yz7Vv/3uVzrCM7LQC/NVV0CUnY
# SVgaf5I25lGSDvMmfRxNF7zJ7EMm0L9BX0CpRET0medXh55QH1dUqD79dGMvsVBl
# CeZYQi5DGky08CVHWfoEHpPUJkZKUIGy3r54t/xnFeHJV4QeD2PW6WK61l9VLupc
# xigIBCU5uA4rqfJMlxwHPw1S9e3vL4IPAgMBAAGjgfIwge8wHwYDVR0jBBgwFoAU
# oBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYDVR0OBBYEFFN5v1qqK0rPVIDh2JvAnfKy
# A2bLMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBEGA1UdIAQKMAgw
# BgYEVR0gADBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNv
# bS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQwF
# AAOCAQEAGIdR3HQhPZyK4Ce3M9AuzOzw5steEd4ib5t1jp5y/uTW/qofnJYt7wNK
# fq70jW9yPEM7wD/ruN9cqqnGrvL82O6je0P2hjZ8FODN9Pc//t64tIrwkZb+/UNk
# fv3M0gGhfX34GRnJQisTv1iLuqSiZgR2iJFODIkUzqJNyTKzuugUGrxx8VvwQQuY
# AAoiAxDlDLH5zZI3Ge078eQ6tvlFEyZ1r7uq7z97dzvSxAKRPRkA0xdcOds/exgN
# Rc2ThZYvXd9ZFk8/Ub3VRRg/7UqO6AZhdCMWtQ1QcydER38QXYkqa4UxFMToqWpM
# gLxqeM+4f452cpkMnf7XkQgWoaNflTCCBfUwggPdoAMCAQICEB2iSDBvmyYY0ILg
# ln0z02owDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpO
# ZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVT
# RVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmlj
# YXRpb24gQXV0aG9yaXR5MB4XDTE4MTEwMjAwMDAwMFoXDTMwMTIzMTIzNTk1OVow
# fDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
# A1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQwIgYDVQQD
# ExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCGIo0yhXoYn0nwli9jCB4t3HyfFM/jJrYlZilAhlRGdDFi
# xRDtsocnppnLlTDAVvWkdcapDlBipVGREGrgS2Ku/fD4GKyn/+4uMyD6DBmJqGx7
# rQDDYaHcaWVtH24nlteXUYam9CflfGqLlR5bYNV+1xaSnAAvaPeX7Wpyvjg7Y96P
# v25MQV0SIAhZ6DnNj9LWzwa0VwW2TqE+V2sfmLzEYtYbC43HZhtKn52BxHJAteJf
# 7wtF/6POF6YtVbC3sLxUap28jVZTxvC6eVBJLPcDuf4vZTXyIuosB69G2flGHNyM
# fHEo8/6nxhTdVZFuihEN3wYklX0Pp6F8OtqGNWHTAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUDuE6qFM6MdWK
# vsG7rWcaA4WtNA4wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0g
# ADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNF
# UlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEE
# ajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVz
# ZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAE1jUO1HNEphpNveaiqMm/EA
# AB4dYns61zLC9rPgY7P7YQCImhttEAcET7646ol4IusPRuzzRl5ARokS9At3Wpwq
# QTr81vTr5/cVlTPDoYMot94v5JT3hTODLUpASL+awk9KsY8k9LOBN9O3ZLCmI2pZ
# aFJCX/8E6+F0ZXkI9amT3mtxQJmWunjxucjiwwgWsatjWsgVgG10Xkp1fqW4w2y1
# z99KeYdcx0BNYzX2MNPPtQoOCwR/oEuuu6Ol0IQAkz5TXTSlADVpbL6fICUQDRn7
# UJBhvjmPeo5N9p8OHv4HURJmgyYZSJXOSsnBf/M6BZv5b9+If8AjntIeQ3pFMcGc
# TanwWbJZGehqjSkEAnd8S0vNcL46slVaeD68u28DECV3FTSK+TbMQ5Lkuk/xYpMo
# JVcp+1EZx6ElQGqEV8aynbG8HArafGd+fS7pKEwYfsR7MUFxmksp7As9V1DSyt39
# ngVR5UR43QHesXWYDVQk/fBO4+L4g71yuss9Ou7wXheSaG3IYfmm8SoKC6W59J7u
# mDIFhZ7r+YMp08Ysfb06dy6LN0KgaoLtO0qqlBCk4Q34F8W2WnkzGJLjtXX4oemO
# CiUe5B7xn1qHI/+fpFGe+zmAEc3btcSnqIBv5VPU4OOiwtJbGvoyJi1qV3AcPKRY
# LqPzW0sH3DJZ84enGm1YMYICQzCCAj8CAQEwgZAwfDELMAkGA1UEBhMCR0IxGzAZ
# BgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMSQwIgYDVQQDExtTZWN0aWdvIFJTQSBDb2Rl
# IFNpZ25pbmcgQ0ECECwnTfNkELSL/bju5S9Y3lMwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgvtxHfPMMnmUmO6AX+/yAMFfLgBSbjhf4kUzDuQsLQagwDQYJKoZIhvcNAQEB
# BQAEggEAICTjzWPPsAweo7K/mtsqB5BvRzH4fnPMUugX46fedIreVgHZHAQobkbc
# xSgM3FIMBgaS4GOOqw41QVFr9C2r9ybKNH7/9VbTx6/o5dittiPZzppkje1qIFH5
# rsBL317omXK/aEzvB4LYS++Jb/TMExI6p8Iyk2BW55sZ4T/CYJbcLjk2drHmbi54
# y/JWUmntLitMeoWZOVjn+pWnES7+eqEHW2ygycmRtkaM8j+uoYg4pm+P7joO4N4T
# UkoEXwH8StT9aBNrjPXv3jmBTF27enBVKwquvYMXWfgugl5So4uNHv1RKzhW5tyB
# nGNOG0UGw7TGRkf9glDic6OgMRChCw==
# SIG # End signature block
