# Define input/output paths
$inputCsvPath = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\Win_Registry_Queries.csv"
$outputJsonPath = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\output.json"

# Import CSV data
$csvData = Import-Csv -Path $inputCsvPath

# Export local security policy to file
$seceditExportPath = "C:\secpol.cfg"
secedit /export /cfg $seceditExportPath | Out-Null
# Load the policy file contents into memory
$policyContent = Get-Content -Path $seceditExportPath

# Initialize result and error logs
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

        # Switch based on the type of query method
    switch -Wildcard ($row.query_method) {
        "registry" {
            try {
                 # Try to get registry values from the given path
                $regItem = Get-ItemProperty -Path $row.reg_query_path -ErrorAction Stop
                
                # Split and trim reg_query_name to support multiple value names (comma-separated)
                $valueNames = $row.reg_query_name -split ',' | ForEach-Object { $_.Trim() }
                foreach ($name in $valueNames) {
                    if ($regItem.PSObject.Properties.Name -contains $name) {
                        # If value exists, collect the value
                        $queryResult += @{ ($name) = $regItem.$name }
                    } else {
                        # Key found, but value is not present
                        $queryResult += @{ ($name) = "Key Found, Value Not Present" }
                    }
                }
            } catch {
                 # Registry key not found or inaccessible
                $queryResult += @{ ($row.reg_query_name) = "Registry Key Not Found" }
                
                # Add error details to error log
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

            # Find line in policy export that matches the setting name
            $line = $policyContent | Where-Object { $_ -match "^\s*$settingName\s*=" }

            if ($line) {
                # Extract the value after '=' and clean up quotes/whitespace
                $sidRaw = ($line -split "=")[1].Trim().Trim('"')
                # Split into multiple entries (usually comma-separated SIDs or names)
                $sidParts = $sidRaw -split ","

                # Try to resolve each SID or user to a readable NTAccount name
                $resolvedNames = $sidParts | ForEach-Object {
                    $entry = $_.Trim()
                    if ($entry -like "*S-1-*") {
                        try {
                            $sidObj = New-Object System.Security.Principal.SecurityIdentifier ($entry.TrimStart('*'))
                            $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            $entry # If failed, return raw SID
                        }
                    } else {
                        try {
                            # Attempt direct translation of NTAccount
                            (New-Object System.Security.Principal.NTAccount($entry)).Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            $entry
                        }
                    }
                }

                $resolvedNames = $resolvedNames | ForEach-Object {
                    $_ -replace "^(NT AUTHORITY\\|BUILTIN\\|RESTRICTED SERVICES\\)", ""  # Clean prefixes like "NT AUTHORITY\", "BUILTIN\", etc.
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

                # Check for command failure or empty output
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

    # Check if audit_name already exists in results (group multiple values under one audit)
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
