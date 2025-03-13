import json
import csv

# Define input and output file names
input_file = "../entities.ftm.json"
output_file = "../entity_ids.csv"

# Open the JSON file and read line by line
with open(input_file, "r", encoding="utf-8") as json_file, open(output_file, "w", newline="", encoding="utf-8") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["id"])  # Write header
    
    for line in json_file:
        try:
            data = json.loads(line.strip())  # Parse JSON line
            if "id" in data:
                csv_writer.writerow([data["id"]])  # Write ID to CSV
        except json.JSONDecodeError as e:
            print(f"Skipping invalid JSON line: {e}")

print(f"Extraction complete. IDs saved in {output_file}")
