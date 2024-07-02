file = input("PCAP file: ")

with open(file, "rb") as cap_file:
    b_block_type = cap_file.read(4)
    b_block_length = cap_file.read(4)
    b_byteorder_magic = cap_file.read(4)
    b_major_version = cap_file.read(2)
    b_minor_version = cap_file.read(2)
    b_section_length = cap_file.read(8)

    byteorder = "big" if b_byteorder_magic == b"\x1a\x2b\x3c\x4d" else "little"

    block_length = int.from_bytes(b_block_length, byteorder)

    LENGTH = 28  # Length of all fields except options

    options = cap_file.read(block_length - LENGTH)

    cap_file.read(4)  # Read redundant length
