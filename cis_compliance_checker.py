import json
import csv
import operator

# File paths
json_path = "output.json"
input_csv_path = "cis_compliance_input.csv"
output_csv_path = "cis_compliance_results.csv"

# Supported comparison operators
ops = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
    "in": lambda a, b: a in b,
    "not in": lambda a, b: a not in b
}

# Load JSON configuration data
try:
    with open(json_path, "r", encoding="utf-8-sig") as jf:
        json_data = json.load(jf)
except json.JSONDecodeError:
    print("ERROR: Could not parse JSON. Is the output.json file empty or invalid?")
    exit(1)

# Create lookup from audit_name to actual value
value_map = {
    item["audit_name"].strip(): str(item["value"]).strip()
    for item in json_data
}

# Process input CSV and evaluate each row
results = []
with open(input_csv_path, newline='', encoding='utf-8-sig') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        audit_name = row["audit_name"].strip()
        description = row["description"].strip()
        settings = row["settings"].strip()
        operator_func = ops.get(row["operator"], operator.eq)
        disallowed_values = [v.strip() for v in row.get("disallowed_values", "").split(",") if v.strip()]
        remediation_original = row["remediation"].strip().strip('"')
        actual_value = value_map.get(audit_name, "").strip()

        # Default to error if data is missing
        if not audit_name or settings == "" or actual_value == "":
            status = "Error"
        elif actual_value in disallowed_values:
            status = "Fail"
        else:
            # Type-safe comparison logic
            if settings.isdigit() and actual_value.isdigit():
                try:
                    comparison_result = operator_func(int(actual_value), int(settings))
                    status = "Pass" if comparison_result else "Fail"
                except Exception as e:
                    print(f"[ERROR] Comparison failed for {audit_name}: {e}")
                    status = "Error"
            elif settings.isdigit() != actual_value.isdigit():
                print(f"[TYPE ERROR] Type mismatch for {audit_name}: expected '{settings}', actual '{actual_value}'")
                status = "Error"
            else:
                try:
                    comparison_result = operator_func(actual_value, settings)
                    status = "Pass" if comparison_result else "Fail"
                except Exception as e:
                    print(f"[ERROR] String comparison failed for {audit_name}: {e}")
                    status = "Error"

        # Include remediation only if status is Fail
        remediation_output = remediation_original if status == "Fail" else ""

        # Save result
        results.append({
            "audit_name": audit_name,
            "description": description,
            "current_settings": actual_value,
            "status": status,
            "remediation": remediation_output
        })

# Write to output CSV
with open(output_csv_path, "w", newline='', encoding='utf-8-sig') as f:
    fieldnames = ["audit_name", "description", "current_settings", "status", "remediation"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print("Compliance results saved to:", output_csv_path)
