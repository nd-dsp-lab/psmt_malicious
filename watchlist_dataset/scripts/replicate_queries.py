import csv
import itertools

# Read the queries from query.csv, skipping the header
with open("../query.csv", "r", newline="") as infile:
    reader = csv.reader(infile)
    header = next(reader)  # Skip the header line
    queries = [row[0] for row in reader if row]  # Get non-empty rows

# Open repliced_query.csv for writing and write 65536 lines by repeating the queries
with open("./repliced_query.csv", "w", newline="") as outfile:
    writer = csv.writer(outfile)
    # Use itertools.islice with itertools.cycle to write exactly 65536 lines
    for query in itertools.islice(itertools.cycle(queries), 65536):
        writer.writerow([query])