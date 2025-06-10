# Define input/output paths
$inputCsvPath = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\Win_Registry_Queries.csv"
$outputJsonPath = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\output.json"

# Import CSV data
$csvData = Import-Csv -Path $inputCsvPath

# Export local security policy to file
$seceditExportPath = "C:\secpol.cfg"
secedit /export /cfg $seceditExportPath | Out-Null
$policyContent = Get-Content -Path $seceditExportPath

$results = @()
$errorLog = @()

# Get current user's SID
$currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Loop through each audit entry
foreach ($row in $csvData) {
    $queryResult = @()

    # Replace [USER SID] placeholder with actual SID
    if ($row.reg_query_path -like "*[USER SID]*") {
        $row.reg_query_path = $row.reg_query_path -replace '\[USER SID\]', $currentUserSid
    }

    switch -Wildcard ($row.query_method) {
        "registry" {
            try {
                $regItem = Get-ItemProperty -Path $row.reg_query_path -ErrorAction Stop

                $valueNames = $row.reg_query_name -split ',' | ForEach-Object { $_.Trim() }
                foreach ($name in $valueNames) {
                    if ($regItem.PSObject.Properties.Name -contains $name) {
                        $queryResult += @{ ($name) = $regItem.$name }
                    } else {
                        $queryResult += @{ ($name) = "Key Found, Value Not Present" }
                    }
                }
            } catch {
                $queryResult += @{ ($row.reg_query_name) = "Registry Key Not Found" }

                $errorLog += [PSCustomObject]@{
                    Timestamp    = (Get-Date).ToString("s")
                    QueryPath    = $row.reg_query_path
                    QueryName    = $row.reg_query_name
                    ErrorMessage = $_.Exception.Message
                    ErrorType    = $_.FullyQualifiedErrorId
                }
            }
        }

        "local_group_policy" {
            $settingName = $row.reg_query_name
            $line = $policyContent | Where-Object { $_ -match "^\s*$settingName\s*=" }

            if ($line) {
                $sidRaw = ($line -split "=")[1].Trim().Trim('"')
                $sidParts = $sidRaw -split ","

                $resolvedNames = $sidParts | ForEach-Object {
                    $entry = $_.Trim()
                    if ($entry -like "*S-1-*") {
                        try {
                            $sidObj = New-Object System.Security.Principal.SecurityIdentifier ($entry.TrimStart('*'))
                            $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            $entry
                        }
                    } else {
                        try {
                            (New-Object System.Security.Principal.NTAccount($entry)).Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            $entry
                        }
                    }
                }

                $resolvedNames = $resolvedNames | ForEach-Object {
                    $_ -replace "^(NT AUTHORITY\\|BUILTIN\\|RESTRICTED SERVICES\\)", ""
                }

                $queryResult += @{ ($settingName) = ($resolvedNames -join ", ") }
            } else {
                $queryResult += @{ ($settingName) = "Not Applicable" }
            }
        }

        "auditpol" {
            try {
                $subcategory = $row.reg_query_name
                $fullCommand = "$($row.reg_query_path):`"$subcategory`""
                $auditOutput = Invoke-Expression $fullCommand 2>$null

                if ($LASTEXITCODE -ne 0 -or !$auditOutput) {
                    $queryResult += @{ ($subcategory) = "Error" }
                } else {
                    $value = "Unknown"
                    foreach ($line in $auditOutput) {
                        if ($line -match "^\s*$subcategory\s+(.+)$") {
                            $value = $matches[1].Trim()
                            break
                        }
                    }
                    $queryResult += @{ ($subcategory) = $value }
                }
            } catch {
                $queryResult += @{ ($row.reg_query_name) = "Auditpol Command Failed" }

                $errorLog += [PSCustomObject]@{
                    Timestamp    = (Get-Date).ToString("s")
                    QueryPath    = "auditpol"
                    QueryName    = $row.reg_query_name
                    ErrorMessage = $_.Exception.Message
                    ErrorType    = $_.FullyQualifiedErrorId
                }
            }
        }

        Default {
            $queryResult += @{ ($row.reg_query_name) = "Unknown query_method" }
        }
    }

    # Check for existing audit_name entry and group results
    $existing = $results | Where-Object { $_.audit_name -eq $row.audit_name }

    if ($existing) {
        $existing.Result += $queryResult
    } else {
        $results += [PSCustomObject]@{
            audit_name     = $row.audit_name
            reg_query_path = $row.reg_query_path
            query_method   = $row.query_method
            Result         = $queryResult
        }
    }
}

# Export results to JSON
$json = $results | ConvertTo-Json -Depth 3
$json = $json -replace '\\u0027', "'"  # Replace Unicode escaped single quotes with actual single quotes
[System.IO.File]::WriteAllText($outputJsonPath, $json, [System.Text.Encoding]::UTF8)

Write-Host "Audit results saved to $outputJsonPath"
