import csv
import json
import sys
import re

# File paths (can be overridden by command-line arguments)
json_path = "output.json"
input_csv_path = "cis_compliance_input.csv"
output_csv_path = "cis_compliance_results.csv"

# Load JSON from file
def load_json(json_path):
    with open(json_path, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

# Load CSV into list of dictionaries
def load_csv(csv_path):
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))

# Supported operator functions
operator_functions = {
    '==': lambda c, e: str(c).strip().lower() == str(e).strip().lower(),
    '!=': lambda c, e: str(c).strip().lower() != str(e).strip().lower(),
    '>=': lambda c, e: float(c) >= float(e),
    '<=': lambda c, e: float(c) <= float(e),
    '>': lambda c, e: float(c) > float(e),
    '<': lambda c, e: float(c) < float(e),
    'in': lambda c, e: e.strip().lower() in str(c).lower(),
    'contains_all': lambda c, e: set(map(str.strip, e.split(','))).issubset(
        set(map(str.strip, str(c).split(',')))
    ),
    'expression': lambda c, e: eval(e.replace('x', str(float(c))), {"__builtins__": {}}, {}),
    'only': lambda c, e: set(map(str.strip, str(c).lower().split(','))) == set(map(str.strip, str(e).lower().split(','))),
    'one_of': lambda c, e: any(str(c).strip().lower() == val.strip().lower() for val in e.split(','))
}

# Normalize raw value based on context
def normalize_value_dynamic(audit_name, reg_query_path, value, expected_value):
    expected_str = str(expected_value).strip().lower()

    if isinstance(value, list):# If value is list (REG_MULTI_SZ), convert to normalized string (comma separated)
        cleaned = [v.strip() for v in value if v.strip() != ""]
        if len(cleaned) == 0:
            return ""
        else:
            return ",".join(cleaned)

    if isinstance(value, str) and "not found" in value.lower():
        return "Not Found"

    if isinstance(value, str):
        value = value.replace('\\\\', '\\')
    if isinstance(expected_value, str):
        expected_value = expected_value.replace('\\\\', '\\')

    # Registry Service Start Type Mapping
    service_start_type_map = {
        2: "Automatic",
        3: "Manual",
        4: "Disabled"
    }

    if reg_query_path and "HKLM" in reg_query_path.lower():
        try:
            int_value = int(value)
            if expected_str in ["disabled", "manual", "automatic"]:
                return service_start_type_map.get(int_value, str(int_value))
        except Exception:
            pass

    # New: Handle 0/1 boolean mapping for Enabled/Disabled expected values
    try:
        int_value = int(value)
        if expected_str in ["enabled", "disabled"]:
            if int_value == 1:
                return "Enabled"
            elif int_value == 0:
                return "Disabled"
    except Exception:
        pass

    # Boolean (GPO): 0 or 1 to Disabled/Enabled (some fallback)
    value_str = str(value).strip()
    if value_str in ["\u0000", "\\u0000", "null", "None", ""]:
        return ""  # or "Not Set" — something consistent

    return str(value_str)



# Compare values using the specified operator
def compare_values(current, expected, operator_key):
    try:
        if operator_key in operator_functions:
            return operator_functions[operator_key](current, expected)
        else:
            return False
    except Exception:
        return False

# Extract audit ID prefix (e.g., "2.2.35" from "2.2.35 Some Policy")
def extract_audit_id(full_name):
    match = re.match(r"^\d+(\.\d+)+", full_name)
    return match.group(0) if match else full_name.strip().lower()

# Main compliance check logic
def evaluate_compliance(output_data, input_data):
    results = []
    missing_values = ['Not Found', 'Registry Key Not Found', 'Key Found, Value Not Present']

    for policy in input_data:
        audit_name = policy['audit_name']
        expected_raw = policy['settings']
        operator = policy['operator']
        remediation = policy['remediation']

        audit_id = extract_audit_id(audit_name)

        # Find matching audit entry by prefix
        current_entry = next(
            (entry for entry in output_data if extract_audit_id(entry['audit_name']) == audit_id),
            None
        )

        if current_entry is None:
            raw_value = 'Not Found'
            reg_query_path = ''
        else:
            raw_value = current_entry.get('value', 'Not Found')
            reg_query_path = current_entry.get('reg_query_path', '')

        expected_normalized = normalize_value_dynamic(audit_name, reg_query_path, expected_raw, expected_raw)
        actual_normalized = normalize_value_dynamic(audit_name, reg_query_path, raw_value, expected_raw)

        if actual_normalized in missing_values:
            status = 'Fail'
            display_value = raw_value  # show the actual error string

        else:
            result_ok = compare_values(actual_normalized, expected_normalized, operator)
            status = 'Pass' if result_ok else 'Fail'
            display_value = actual_normalized
        
        print(f"DEBUG: Audit: {audit_name}")
        print(f"DEBUG: Raw value: '{raw_value}'")
        print(f"DEBUG: Normalized actual: '{actual_normalized}'")
        print(f"DEBUG: Expected: '{expected_raw}' → Normalized: '{expected_normalized}'")
        print(f"DEBUG: Operator: '{operator}'")
        print(f"DEBUG: Status: '{status}'") 

        results.append({
            'audit_name': audit_name,
            'current_settings': display_value,
            'status': status,
            'remediation': remediation if status == 'Fail' else ''
        })

    return results

# Write final result to CSV
def write_result_csv(result_data, output_path):
    fieldnames = ['audit_name', 'current_settings', 'status', 'remediation']
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(result_data)

# Entry point
def main(output_json_path, input_csv_path, result_csv_path):
    output_data = load_json(output_json_path)
    input_data = load_csv(input_csv_path)
    result_data = evaluate_compliance(output_data, input_data)
    write_result_csv(result_data, result_csv_path)
    print(f"\nCompliance check completed. Results saved to: {result_csv_path}")

# Run with optional CLI support
if __name__ == '__main__':
    if len(sys.argv) == 4:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        main(json_path, input_csv_path, output_csv_path)
