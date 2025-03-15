import sys
import csv
import hashlib

def hash_id(id_str, num_bits):
    """
    Hashes the given string ID using SHA-256 and returns the first `num_bits` bits as an integer.
    """
    # SHA-256 produces 32 bytes (256 bits)
    hash_bytes = hashlib.sha256(id_str.encode('utf-8')).digest()
    
    # Number of bytes needed to cover num_bits
    needed_bytes = (num_bits + 7) // 8  # integer division rounding up
    truncated_bytes = hash_bytes[:needed_bytes]
    
    # Convert those bytes to an integer
    shift_size = needed_bytes * 8 - num_bits  # how many excess bits must be shifted out
    hashed_int = int.from_bytes(truncated_bytes, 'big') >> shift_size
    
    return hashed_int


def split_into_chunks(hashed_int, bit_size, kappa):
    """
    Splits the integer `hashed_int` (already truncated to bit_size bits) 
    into `kappa` chunks. Each chunk will be bit_size // kappa bits long.
    """
    if bit_size % kappa != 0:
        raise ValueError(f"bit_size ({bit_size}) must be divisible by kappa ({kappa}).")
    
    chunk_size = bit_size // kappa
    chunks = []

    for i in range(kappa):
        # Calculate where to shift to isolate the relevant chunk
        shift_amount = bit_size - (i + 1) * chunk_size
        # Extract chunk_size bits
        chunk = (hashed_int >> shift_amount) & ((1 << chunk_size) - 1)
        chunks.append(chunk)

    return chunks


def main():
    if len(sys.argv) != 3:
        print("Usage: python do_hash_and_chunk.py <bit_size> <kappa>")
        sys.exit(1)

    bit_size = int(sys.argv[1])
    kappa = int(sys.argv[2])

    input_file = "./entity_ids.csv"
    output_file = f"./hashed_chunks_{bit_size}_{kappa}.csv"

    with open(input_file, newline='', encoding='utf-8') as infile, \
         open(output_file, 'w', newline='', encoding='utf-8') as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # Assuming the first row of entity_ids.csv is a header.
        # Skip the header from the input file.
        header = next(reader, None)  # if there's no header, it won't crash

        # Write the header for the output file (one column: 'chunk')
        writer.writerow(["chunk"])

        for row in reader:
            if row:  # skip empty lines
                entity_id = row[0]
                
                # 1) Hash the ID to `bit_size` bits
                hashed_value = hash_id(entity_id, bit_size)
                
                # 2) Split into `kappa` chunks
                chunks = split_into_chunks(hashed_value, bit_size, kappa)

                # 3) Write each chunk as a separate row
                for c in chunks:
                    writer.writerow([c])

    print(f"Hashed chunks saved to {output_file}")


if __name__ == "__main__":
    main()
