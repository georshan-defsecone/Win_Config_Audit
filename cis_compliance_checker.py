import json
import csv
import operator

# File paths
json_path = "output.json"
input_csv_path = "cis_compliance_input.csv"
output_csv_path = "cis_compliance_results.csv"

# Operators
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

# Load JSON
with open(json_path, "r", encoding="utf-8-sig") as jf:
    json_data = json.load(jf)

# Map audit_name -> actual value
value_map = {
    item["audit_name"].strip(): str(item["value"]).strip()
    for item in json_data
}

# Compare CSV entries
results = []
with open(input_csv_path, newline='', encoding='utf-8-sig') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        audit = row["audit_name"].strip()
        expected = row["settings"].strip()
        actual = value_map.get(audit, "")
        operator_func = ops.get(row["operator"], operator.eq)
        remediation = row["remediation"].strip().strip('"')
        description = row["description"].strip()

        # Default handling
        if not audit or expected == "" or actual == "":
            status = "Error"
        elif actual in ["Not Applicable", "Key Found, Value Not Present", "Registry Key Not Found"]:
            status = "Fail"
        else:
            try:
                # Try comparing as int if both are numbers
                if expected.isdigit() and actual.isdigit():
                    status = "Pass" if operator_func(int(actual), int(expected)) else "Fail"
                else:
                    status = "Pass" if operator_func(actual, expected) else "Fail"
            except Exception:
                status = "Error"

        results.append({
            "audit_name": audit,
            "description": description,
            "current_settings": actual,
            "status": status,
            "remediation": remediation if status == "Fail" else ""
        })

# Output CSV
with open(output_csv_path, "w", newline='', encoding='utf-8-sig') as f:
    writer = csv.DictWriter(f, fieldnames=["audit_name", "description", "current_settings", "status", "remediation"])
    writer.writeheader()
    writer.writerows(results)

print("Compliance results saved to:", output_csv_path)
