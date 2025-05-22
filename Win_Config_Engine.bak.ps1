# Define input/output paths
$inputCsvPath = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\Win_Registry_Queries.csv"
$outputJsonPath = "C:\Users\Welcome\Desktop\Win Config Audit Final\Win_Config_Audit\output.json"

# Import CSV data
$csvData = Import-Csv -Path $inputCsvPath

# Export local security policy to file
$seceditExportPath = "C:\secpol.cfg"
secedit /export /cfg $seceditExportPath | Out-Null
$policyContent = Get-Content -Path $seceditExportPath

# Initialize results array
$results = @()

# Loop through each audit entry
foreach ($row in $csvData) {
    $queryResult = ""

    if ($row.query_method -eq "registry") {
        try {
            $regItem = Get-ItemProperty -Path $row.reg_query_path -ErrorAction Stop
            if ($regItem.PSObject.Properties[$row.reg_query_name]) {
                $queryResult = $regItem.($row.reg_query_name)
            } else {
                $queryResult = "Key Found, Value Not Present"
            }
        } catch {
            $queryResult = "Registry Key Not Found"
        }
    } elseif ($row.query_method -eq "local_group_policy") {
        $settingName = $row.reg_query_name
        $line = $policyContent | Where-Object { $_ -match "^\s*$settingName\s*=" }
        if ($line) {
            $sidRaw = ($line -split "=")[1].Trim().Trim('"')
            $sidParts = $sidRaw -split ","
            $resolvedNames = $sidParts | ForEach-Object {
                $entry = $_.Trim()
                if ($entry -match "^\*S-1-") {
                    try {
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier ($entry.TrimStart('*'))
                        $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                    } catch {
                        $entry
                    }
                } else {
                    $entry
                }
            }

            # Remove unwanted prefixes
            $resolvedNames = $resolvedNames | ForEach-Object {
                $_ -replace "^(NT AUTHORITY\\|BUILTIN\\|RESTRICTED SERVICES\\)", ""
            }

            $queryResult = ($resolvedNames -join ", ")
        } else {
            $queryResult = "Not Applicable"
        }
    } else {
        $queryResult = "Unknown query_method"
    }

    # Save the result in the results array
    $results += [PSCustomObject]@{
        audit_name     = $row.audit_name
        reg_query_path = $row.reg_query_path
        query_method   = $row.query_method
        value          = $queryResult
    }
}

# Export results to JSON
$json = $results | ConvertTo-Json -Depth 3
$json = $json -replace '\\u0027', "'"  # Replace Unicode escaped single quotes with actual single quotes
[System.IO.File]::WriteAllText($outputJsonPath, $json, [System.Text.Encoding]::UTF8)

Write-Host "Audit results saved to $outputJsonPath"
