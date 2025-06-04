import csv
import json
import sys
import re
import ast  # For safely parsing map dict strings

# Default file paths (can be overridden via CLI)
json_path = "output.json"
input_csv_path = "cis_compliance_input.csv"
output_csv_path = "cis_compliance_results.csv"

# Load JSON
def load_json(json_path):
    with open(json_path, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

# Load CSV
def load_csv(csv_path):
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))

# Operator logic
OPERATORS = {
    '==': lambda current, expected: str(current).strip().lower() == str(expected).strip().lower(),
    '!=': lambda current, expected: str(current).strip().lower() != str(expected).strip().lower(),
    '>=': lambda current, expected: float(current) >= float(expected),
    '<=': lambda current, expected: float(current) <= float(expected),
    '>': lambda current, expected: float(current) > float(expected),
    '<': lambda current, expected: float(current) < float(expected),
    'in': lambda current, expected: expected.strip().lower() in str(current).lower(),
    'contains_all': lambda current, expected: set(map(str.strip, expected.split(','))).issubset(set(map(str.strip, str(current).split(',')))),
    'expression': lambda current, expected: eval(expected.replace('x', str(float(current))), {"__builtins__": {}}, {}),
    'only': lambda current, expected: set(map(str.strip, str(current).lower().split(','))) == set(map(str.strip, str(expected).lower().split(','))),
    'one_of': lambda current, expected: any(str(current).strip().lower() == val.strip().lower() for val in expected.split(','))
}

# Normalize and apply value_map if provided
def normalize_value(value, value_map=None):
    if value_map:
        try:
            # Map by raw or string value
            mapped_value = value_map.get(value, value_map.get(str(value)))
            if mapped_value is not None:
                return str(mapped_value).strip()
        except Exception:
            pass

    # Normalize lists
    if isinstance(value, list):
        cleaned = [v.strip() for v in value if v.strip()]
        return ",".join(cleaned) if cleaned else ""

    # Handle common error strings
    value_str = str(value).strip()
    if not value_map and value_str.lower() in ['not found', 'registry key not found', 'key found, value not present', 'null', 'none', '', '\u0000', '\\u0000']:
        return "Not Found"
    return value_str

# Compare values
def compare_values(current, expected, operator_key):
    try:
        if operator_key in OPERATORS:
            return OPERATORS[operator_key](current, expected)
        else:
            print(f"Warning: Unknown operator '{operator_key}'")
            return False
    except Exception:
        return False

# Extract audit ID prefix
def extract_audit_id(full_name):
    match = re.match(r"^\d+(\.\d+)+", full_name)
    return match.group(0) if match else full_name.strip().lower()

# Core compliance check
def evaluate_compliance(output_data, input_data):
    results = []
    for policy in input_data:
        audit_name = policy['audit_name']
        expected_raw = policy['settings']
        operator = policy['operator']
        remediation = policy.get('remediation', '')

        # Parse value_map
        value_map = None
        if 'map' in policy and policy['map'].strip():
            try:
                value_map = ast.literal_eval(policy['map'])
            except Exception as e:
                print(f"Warning: Failed to parse map for audit '{audit_name}': {e}")

        audit_id = extract_audit_id(audit_name)
        current_entry = next((entry for entry in output_data if extract_audit_id(entry['audit_name']) == audit_id), None)

        raw_value = current_entry.get('value', 'Not Found') if current_entry else 'Not Found'

        actual_normalized = normalize_value(raw_value, value_map)
        expected_normalized = normalize_value(expected_raw, value_map)

        if actual_normalized == "Not Found":
            status = "Fail"
            display_value = raw_value
        else:
            result_ok = compare_values(actual_normalized, expected_normalized, operator)
            status = "Pass" if result_ok else "Fail"
            display_value = actual_normalized

        results.append({
            'audit_name': audit_name,
            'current_settings': display_value,
            'status': status,
            'remediation': remediation if status == 'Fail' else ''
        })

    return results

# Save results
def write_result_csv(result_data, output_path):
    fieldnames = ['audit_name', 'current_settings', 'status', 'remediation']
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(result_data)

# Main entry
def main(output_json_path, input_csv_path, result_csv_path):
    output_data = load_json(output_json_path)
    input_data = load_csv(input_csv_path)
    result_data = evaluate_compliance(output_data, input_data)
    write_result_csv(result_data, result_csv_path)
    print(f"\nCompliance check completed. Results saved to: {result_csv_path}")

# CLI support
if __name__ == '__main__':
    if len(sys.argv) == 4:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        main(json_path, input_csv_path, output_csv_path)
