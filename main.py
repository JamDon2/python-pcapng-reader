from io import BufferedReader


class PCAPNGReader:
    SHB_OPTION_NAMES = {2: "hardware", 3: "os", 4: "application"}
    IDB_OPTION_NAMES = {
        2: "name",
        3: "description",
        9: "time_resolution",
        11: "filter",
        12: "os",
    }

    def __init__(self, file: BufferedReader) -> None:
        self.file = file

        self.file.read(4)  # Block type
        b_block_length = self.file.read(4)
        b_byteorder_magic = self.file.read(4)
        self.file.read(2)  # Major version
        self.file.read(2)  # Minor version
        self.file.read(8)  # Section length

        self.byteorder = "big" if b_byteorder_magic == b"\x1a\x2b\x3c\x4d" else "little"

        block_length = int.from_bytes(b_block_length, self.byteorder)

        LENGTH = 28  # Length of all fields except options

        self.options = self.options_parser(
            self.file.read(block_length - LENGTH), self.SHB_OPTION_NAMES
        )

        self.file.read(4)  # Read redundant length

        print(self.options)

    def options_parser(self, options: bytes, option_names: dict[int, str]):
        offset = 0

        options_dict = {}

        while offset < len(options):
            option = int.from_bytes(options[offset + 0 : offset + 2], self.byteorder)

            if option == 0:
                break

            length = int.from_bytes(options[offset + 2 : offset + 4], self.byteorder)

            data = options[offset + 4 : offset + 4 + length]

            total_length = 4 + length

            offset += total_length + 3  # Add length plus 3 padding to offset

            key = option_names[option] if option in option_names else option

            options_dict[key] = data.decode()

        return options_dict


if __name__ == "__main__":
    # file = input("PCAP file: ")
    file = "python.pcapng"

    with open(file, "rb") as cap_file:
        PCAPNGReader(cap_file)
