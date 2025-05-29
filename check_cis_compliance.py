import csv
import json
import sys

# File paths (used when no command-line arguments are passed)
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

# Dynamic operator functions
operator_functions = {
    '==': lambda c, e: str(c).strip() == str(e).strip(),
    '>=': lambda c, e: float(c) >= float(e),
    '<=': lambda c, e: float(c) <= float(e),
    '>': lambda c, e: float(c) > float(e),
    '<': lambda c, e: float(c) < float(e),
    'in': lambda c, e: e.strip() in str(c),
    'contains_all': lambda c, e: set(map(str.strip, e.split(','))).issubset(
        set(map(str.strip, str(c).split(',')))
    ),
    'expression': lambda c, e: eval(e.replace('x', str(float(c))), {"__builtins__": {}}, {})
}

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
    for policy in input_data:
        audit_name = policy['audit_name']
        expected = policy['settings']
        operator = policy['operator']
        remediation = policy['remediation']

        current_entry = next((entry for entry in output_data if entry['audit_name'] == audit_name), None)
        current_value = current_entry['value'] if current_entry else 'Not Found'

        if current_value == 'Not Found':
            status = 'Not Found'
        else:
            status = 'Pass' if compare_values(current_value, expected, operator) else 'Fail'

        # Print status to console
        print(f"{audit_name}: {status}")

        # Only include remediation for failed checks
        remediation_output = remediation if status == 'Fail' else ''

        result.append({
            'audit_name': audit_name,
            'current_settings': current_value,
            'status': status,
            'remediation': remediation_output
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
