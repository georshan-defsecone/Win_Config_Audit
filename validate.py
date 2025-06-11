import csv
import json
import ast  # Safely evaluate the map string

# File paths
json_path = "output.json"
input_csv_path = "cis_compliance_input test.csv"
output_csv_path = "cis_compliance_results test.csv"

# Load audit JSON
def load_json(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)

# Load CSV
def load_csv(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        return list(reader)

# Extract audit ID from audit_name
def extract_audit_id(name):
    return name.split()[0].strip()

# Normalize logical operators
def normalize_expression(expr):
    return expr.replace("&&", "and").replace("||", "or")

# Convert string to int/float if possible
def try_convert(value):
    try:
        return int(value)
    except:
        try:
            return float(value)
        except:
            return str(value).strip()

# Evaluate expression using raw values
def evaluate_condition(condition, result_dict):
    try:
        local_vars = {k: try_convert(v) for k, v in result_dict.items()}
        expression = normalize_expression(condition)
        return eval(expression, {}, local_vars)
    except Exception:
        return False

# For display: convert values using optional mapping
def stringify_current_settings(result_dict, map_str=None):
    map_dict = {}
    if map_str:
        try:
            map_dict = ast.literal_eval(map_str)
        except:
            pass

    # Try evaluating logical-expression based keys
    for label, expr in map_dict.items():
        if isinstance(expr, str) and any(op in expr for op in ("==", "&&", "||", ">", "<")):
            try:
                eval_dict = {k: try_convert(v) for k, v in result_dict.items()}
                if evaluate_condition(expr, eval_dict):
                    return label
            except:
                continue

    # Fallback: normal mapping of individual fields
    display_items = []
    for k, v in result_dict.items():
        v_str = str(v).strip()
        mapped_value = map_dict.get(v_str, v_str)
        display_items.append(f"{k}: {mapped_value}")
    return ", ".join(display_items)

# Main logic
def evaluate_compliance(json_data, csv_rules):
    results = []

    for rule in csv_rules:
        audit_name = rule["audit_name"]
        condition = rule["condition"]
        map_str = rule.get("map", "").strip()
        remediation = rule.get("remediation", "")

        csv_audit_id = extract_audit_id(audit_name)
        matched_entry = next((entry for entry in json_data if extract_audit_id(entry["audit_name"]) == csv_audit_id), None)

        if not matched_entry:
            results.append([audit_name, "Not Found", "Fail", remediation])
            continue

        # Merge all Result dicts
        merged_result = {}
        for item in matched_entry.get("Result", []):
            merged_result.update(item)

        # Evaluate condition using raw values
        eval_dict = {k: try_convert(v) for k, v in merged_result.items()}
        is_pass = evaluate_condition(condition, eval_dict)

        # Display settings using mapping
        current_settings = stringify_current_settings(merged_result, map_str)

        status = "Pass" if is_pass else "Fail"
        results.append([audit_name, current_settings, status, remediation])

    return results

# Write output CSV
def write_csv(path, rows):
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["audit_name", "current_settings", "status", "remediation"])
        writer.writerows(rows)

# Run
if __name__ == "__main__":
    json_data = load_json(json_path)
    csv_rules = load_csv(input_csv_path)
    output = evaluate_compliance(json_data, csv_rules)
    write_csv(output_csv_path, output)
    print(f"Compliance evaluation written to: {output_csv_path}")
