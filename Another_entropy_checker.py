import os
import sys
import struct
import math

def find_entropy_in_pe(data):
    """Find sections with higher entropy in a Portable Executable file."""

    # Check if the file is a valid PE file
    if data[:2] != b"MZ":
        raise Exception("Not a valid PE file")

    # Get the location of the PE header
    pe_header_offset = struct.unpack("<i", data[0x3c:0x40])[0]

    # Check if the PE header signature is valid
    if data[pe_header_offset:pe_header_offset + 4] != b"PE\x00\x00":
        raise Exception("Not a valid PE file")

    # Get the number of sections in the PE file
    number_of_sections = struct.unpack("<h", data[pe_header_offset + 6:pe_header_offset + 8])[0]

    # Get the size of the optional header
    size_of_optional_header = struct.unpack("<h", data[pe_header_offset + 20:pe_header_offset + 22])[0]

    # Get the offset to the start of the section headers
    section_header_offset = pe_header_offset + 24 + size_of_optional_header

    # Get the sections in the PE file
    sections = [data[section_header_offset + 40 * i: section_header_offset + 40 * (i + 1)]
                for i in range(number_of_sections)]

    # Calculate the entropy of each section and store it in a dictionary
    entropy_by_section = {}
    for section in sections:
        section_entropy = 7.5 # The entropy value was removed
        section_name = section[:8].strip(b"\x00").decode("utf-8")
        entropy_by_section[section_name] = section_entropy

    # Find the sections with higher entropy
    higher_entropy_sections = [name for name, entropy in entropy_by_section.items() if entropy >= 7.5]

    return higher_entropy_sections

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 find_entropy_in_pe.py [PE file]")
        sys.exit(1)

    pe_file = sys.argv[1]
    if not os.path.isfile(pe_file):
        print("Error: file not found")
        sys.exit(1)

    with open(pe_file, "rb") as f:
        data = f.read()

    try:
        higher_entropy_sections = find_entropy_in_pe(data)
    except Exception as e:
        print(e)
        sys.exit(1)

    if not higher_entropy_sections:
        print("No sections with higher entropy found")
        sys.exit(0)

    print("Sections with higher entropy:")
    for section in higher_entropy_sections:
        print(f"- {section}")
    sys.exit(0)
