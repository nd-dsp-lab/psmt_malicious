import hashlib
import csv

# Input and output file names
input_file = "../entity_ids.csv"
output_file = "../hashed_entity_ids.csv"

def hash_id(id_str):
    """Hashes the given ID using SHA-256 and returns the first 77 bits as an integer."""
    hash_obj = hashlib.sha256(id_str.encode('utf-8')).digest()  # SHA-256 hash (32 bytes)
    first_10_bytes = hash_obj[:10]  # Get the first 10 bytes (80 bits)
    
    # Convert to an integer and truncate to 77 bits
    hashed_int = int.from_bytes(first_10_bytes, "big") >> 3  # Shift right by 3 bits to get 77 bits
    
    return hashed_int  # Return as integer

# Process the file
with open(input_file, newline='', encoding='utf-8') as infile, \
     open(output_file, 'w', newline='', encoding='utf-8') as outfile:

    reader = csv.reader(infile)
    writer = csv.writer(outfile)

    header = next(reader)  # Read header
    writer.writerow(["hashed_id"])  # Write new header

    for row in reader:
        if row:  # Skip empty lines
            hashed_value = hash_id(row[0])
            writer.writerow([hashed_value])

print(f"Hashed IDs saved to {output_file}")
