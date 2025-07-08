#!/usr/bin/env python3
import csv, json

input_csv  = 'oui.csv'          # your downloaded IEEE CSV
output_json = 'oui_extra.json'  # the file iNetScan will load

mapping = {}
with open(input_csv, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        prefix = row['Assignment'].replace('-', '').upper()
        vendor = row['Organization Name'].strip()
        mapping[prefix] = vendor

with open(output_json, 'w', encoding='utf-8') as f:
    json.dump(mapping, f, indent=2, ensure_ascii=False)

print(f"✅ Wrote {len(mapping)} entries to {output_json}")