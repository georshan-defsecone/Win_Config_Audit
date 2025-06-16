# Define input/output paths
$inputCsvPath   = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\Win_Registry_Queries.csv"
$outputJsonPath = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\output.json"

# Import CSV data
$csvData = Import-Csv -Path $inputCsvPath

# Export local security policy to file
$seceditExportPath = "C:\secpol.cfg"
secedit /export /cfg $seceditExportPath | Out-Null

# Load the policy file contents into memory
$policyContent = Get-Content -Path $seceditExportPath

# Initialize result and error logs
$results   = @()
$errorLog  = @()

# Get current user's SID
$currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Loop through each audit entry
foreach ($row in $csvData) {
    $queryResult = @()

    # Replace [USER SID] placeholder with actual SID
    if ($row.reg_query_path -like "*[USER SID]*") {
        $row.reg_query_path = $row.reg_query_path -replace '\[USER SID\]', $currentUserSid
    }

    # Switch based on the type of query method
    switch -Wildcard ($row.query_method) {

        "registry" {
            try {
                Write-Host "Querying Registry Path: $($row.reg_query_path)"

                $regItem = Get-ItemProperty -Path $row.reg_query_path -ErrorAction Stop

                if ([string]::IsNullOrWhiteSpace($row.reg_query_name)) {
                    Write-Host "No value name provided; dumping all values from key."

                    $allProps = $regItem.PSObject.Properties | Where-Object {
                        $_.Name -notlike "PS*"
                    }

                    foreach ($prop in $allProps) {
                        $queryResult += @{ ($prop.Name) = $prop.Value }
                        Write-Host "Found value '$($prop.Name)': $($prop.Value)"
                    }
                } else {
                    $valueNames = $row.reg_query_name -split ',' | ForEach-Object { $_.Trim() }
                    Write-Host "Checking value names from CSV: $($valueNames -join ', ')"

                    foreach ($name in $valueNames) {
                        $prop = $regItem.PSObject.Properties[$name]
                        if ($prop) {
                            $queryResult += @{ ($name) = $prop.Value }
                            Write-Host "Found value for '$name': $($prop.Value)"
                        } else {
                            $queryResult += @{ ($name) = "Key Found, Value Not Present" }
                            Write-Host "Value '$name' not present in key."
                        }
                    }
                }
            } catch {
                $keyName = if ($row.reg_query_name -ne "") { $row.reg_query_name } else { "RegistryKey" }
                $queryResult += @{ ($keyName) = "Registry Key Not Found" }


                $errorLog += [PSCustomObject]@{
                    Timestamp    = (Get-Date).ToString("s")
                    QueryPath    = $row.reg_query_path
                    QueryName    = $row.reg_query_name
                    ErrorMessage = $_.Exception.Message
                    ErrorType    = $_.FullyQualifiedErrorId
                }

                Write-Host "Error querying registry: $($_.Exception.Message)"
            }
        }

        "local_group_policy" {
            $settingName = $row.reg_query_name

            $line = $policyContent | Where-Object { $_ -match "^\s*$settingName\s*=" }

            if ($line) {
                $sidRaw   = ($line -split "=")[1].Trim().Trim('"')
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

    # Group results under one audit entry if already exists
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
$json = $json -replace '\\u0027', "'"
[System.IO.File]::WriteAllText($outputJsonPath, $json, [System.Text.Encoding]::UTF8)

Write-Host "Audit results saved to $outputJsonPath"
