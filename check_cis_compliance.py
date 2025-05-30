import csv
import json
import sys

# File paths
json_path = "output.json"
input_csv_path = "cis_compliance_input.csv"
output_csv_path = "cis_compliance_results.csv"

def load_json(json_path):
    with open(json_path, 'r', encoding='utf-8-sig') as f:
        return json.load(f)

def load_csv(csv_path):
    rows = []
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

# Operator functions
operator_functions = {
    # Exact equality comparison (case-insensitive string)
    '==': lambda c, e: str(c).strip().lower() == str(e).strip().lower(),

    # Numeric greater than or equal comparison
    '>=': lambda c, e: float(c) >= float(e),

    # Numeric less than or equal comparison
    '<=': lambda c, e: float(c) <= float(e),

    # Numeric greater than comparison
    '>': lambda c, e: float(c) > float(e),

    # Numeric less than comparison
    '<': lambda c, e: float(c) < float(e),

    # Check if expected string is a substring of the current value (case-insensitive)
    'in': lambda c, e: e.strip().lower() in str(c).lower(),

    # Check if all expected comma-separated elements are contained within current comma-separated elements (order-independent)
    'contains_all': lambda c, e: set(map(str.strip, e.split(','))).issubset(
        set(map(str.strip, str(c).split(',')))
    ),

    # Evaluate a mathematical expression where 'x' is replaced by the numeric current value
    'expression': lambda c, e: eval(e.replace('x', str(float(c))), {"__builtins__": {}}, {}),

    # Exact match of comma-separated lists (case-insensitive, order-independent, no extra elements)
    'only': lambda c, e: set(map(str.strip, str(c).lower().split(','))) == set(map(str.strip, str(e).lower().split(','))),
    # 'only': only_operator,


    # 'one_of' operator checks if the current value (c) matches exactly one of the allowed expected values (e).
    # Both c and e are compared case-insensitively, and extra spaces are ignored.
    #"No One" or "" (empty string) are both considered valid.
    'one_of': lambda c, e: any(str(c).strip().lower() == val.strip().lower() for val in e.split(','))
}




def convert_to_numeric(expected_value):
    # Convert 'Enabled'/'Disabled' to 1/0 for numeric comparison
    val = str(expected_value).strip().lower()
    if val == 'enabled':
        return '1'
    elif val == 'disabled':
        return '0'
    return expected_value

def normalize_value_dynamic(audit_name, reg_query_path, value, expected_value):
    expected_str = str(expected_value).strip().lower()

    # Normalize Not Found cases
    if isinstance(value, str) and "not found" in value.lower():
        return "Not Found"

    # Map Windows service registry start types
    service_start_type_map = {
        2: "Automatic",
        3: "Manual",
        4: "Disabled"
    }

    if reg_query_path and "services" in reg_query_path.lower():
        try:
            int_value = int(value)
            if expected_str in ["disabled", "manual", "automatic"]:
                return service_start_type_map.get(int_value, str(int_value))
        except Exception:
            pass  # Fallback to default

    # Local Group Policy: map 0/1 to Enabled/Disabled if expected is like that
    if str(value).strip() in ["0", "1"]:
        if expected_str in ['enabled', 'disabled']:
            return "Enabled" if str(value).strip() == "1" else "Disabled"

    return str(value).strip()

def compare_values(current, expected, operator_key):
    try:
        if operator_key in operator_functions:
            return operator_functions[operator_key](current, expected)
        else:
            return False
    except Exception:
        return False

def evaluate_compliance(output_data, input_data):
    result = []
    missing_values = ['Not Found', 'Registry Key Not Found', 'Key Found, Value Not Present']

    for policy in input_data:
        audit_name = policy['audit_name']
        expected_raw = policy['settings']
        operator = policy['operator']
        remediation = policy['remediation']

        # Find current system entry first to get reg_query_path
        current_entry = next((entry for entry in output_data if entry['audit_name'] == audit_name), None)
        raw_value = current_entry['value'] if current_entry else 'Not Found'
        reg_query_path = current_entry['reg_query_path'] if current_entry else ''

        # Normalize both expected and current values consistently before comparison
        expected_value_normalized = normalize_value_dynamic(audit_name, reg_query_path, expected_raw, expected_raw)
        normalized_value = normalize_value_dynamic(audit_name, reg_query_path, raw_value, expected_raw)

        # print(f"Audit: {audit_name}")
        # print(f"ACTUAL: '{normalized_value}'")
        # print(f"EXPECTED: '{expected_value_normalized}'")

        if normalized_value in missing_values:
            status = 'Fail'      # Mark missing keys/values as Fail
            display_value = 'Not Found'
        else:
            result_ok = compare_values(normalized_value, expected_value_normalized, operator)
            status = 'Pass' if result_ok else 'Fail'
            display_value = normalized_value

        print(f"{audit_name}: {status}")

        result.append({
            'audit_name': audit_name,
            'current_settings': display_value,
            'status': status,
            'remediation': remediation if status == 'Fail' else ''
        })

    return result

def write_result_csv(result_data, output_path):
    fieldnames = ['audit_name', 'current_settings', 'status', 'remediation']
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(result_data)

def main(output_json_path, input_csv_path, result_csv_path):
    output_data = load_json(output_json_path)
    input_data = load_csv(input_csv_path)
    result_data = evaluate_compliance(output_data, input_data)
    write_result_csv(result_data, result_csv_path)
    print(f"\nCompliance check completed. Results saved to: {result_csv_path}")

if __name__ == '__main__':
    if len(sys.argv) == 4:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        main(json_path, input_csv_path, output_csv_path)
