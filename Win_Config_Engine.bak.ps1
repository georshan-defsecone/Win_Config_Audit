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

# Loop through each audit entry
foreach ($row in $csvData) {
    $queryResult = ""

    switch -Wildcard  ($row.query_method) {
        "registry" {
            try {
                $regItem = Get-ItemProperty -Path $row.reg_query_path -ErrorAction Stop

                if ($regItem.PSObject.Properties[$row.reg_query_name]) {
                    $queryResult = $regItem.($row.reg_query_name)
                }
                else {
                    $queryResult = "Key Found, Value Not Present"
                }

            }
            catch {
                if ($_.FullyQualifiedErrorId -like "PathNotFound*") {
                    $queryResult = "Registry Key Not Found"
                }
                else {
                    $queryResult = "Unexpected Error"
                }

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
                    if ($entry -match "^\*S-1-") {
                        try {
                            $sidObj = New-Object System.Security.Principal.SecurityIdentifier ($entry.TrimStart('*'))
                            $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                        }
                        catch {
                            $entry
                        }
                    }
                    else {
                        $entry
                    }
                }

                # Clean known prefixes
                $resolvedNames = $resolvedNames | ForEach-Object {
                    $_ -replace "^(NT AUTHORITY\\|BUILTIN\\|RESTRICTED SERVICES\\)", ""
                }

                $queryResult = ($resolvedNames -join ", ")
            }
            else {
                $queryResult = "Not Applicable"
            }
        }

        "auditpol" {
            try {
                $subcategory = $row.reg_query_name.Trim()
                $auditOutput = & auditpol /get /subcategory:"$subcategory" 2>$null

                if ($LASTEXITCODE -ne 0 -or !$auditOutput) {
                    $queryResult = "Error"  
                }
                else {
                    $queryResult = "Unknown"
                    foreach ($line in $auditOutput) {
                        if ($line -match "^\s*$subcategory\s+(.+)$") {
                            $queryResult = $matches[1].Trim()
                            break
                        }
                    }
                }
            }
            catch {
                $queryResult = "Auditpol Command Failed"

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
            $queryResult = "Unknown query_method"
        }
    }

    # Save the result
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
    