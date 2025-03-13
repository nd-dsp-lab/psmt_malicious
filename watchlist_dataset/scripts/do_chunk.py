import csv

# Input and output file names
input_file = "../hashed_entity_ids.csv"
output_file = "../hashed_chunks.csv"

def split_into_chunks(hashed_int):
    """
    Splits a 77-bit integer into 7 chunks of 11 bits each.
    """
    chunk_size = 11  # Each chunk is 11 bits
    num_chunks = 7   # We need 7 chunks
    chunks = []

    for i in range(num_chunks):
        shift_amount = 77 - (i + 1) * chunk_size  # Compute shift amount for 11-bit chunk
        chunk = (hashed_int >> shift_amount) & ((1 << chunk_size) - 1)  # Extract 11-bit chunk
        chunks.append(chunk)

    return chunks

# Process the file
with open(input_file, newline='', encoding='utf-8') as infile, \
     open(output_file, 'w', newline='', encoding='utf-8') as outfile:

    reader = csv.reader(infile)
    writer = csv.writer(outfile)

    header = next(reader)  # Skip header
    writer.writerow(["chunk"])  # Write new header

    for row in reader:
        if row:  # Skip empty lines
            hashed_int = int(row[0])  # Convert string to integer
            chunks = split_into_chunks(hashed_int)
            
            # Write each chunk sequentially to the file
            for chunk in chunks:
                writer.writerow([chunk])

print(f"Hashed chunks saved to {output_file}")
