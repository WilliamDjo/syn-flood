import struct

with open("synflood.pcap", "rb") as f:
    global_header = f.read(24)
    magic_number = struct.unpack("I", global_header[0:4])[0]

    assert magic_number == 0xA1B2C3D4

    fmt = "<IHHIIII"
    fields = struct.unpack(fmt, global_header)

    header = {
        "magic_number": hex(fields[0]),
        "version_major": fields[1],
        "version_minor": fields[2],
        "timezone_offset": fields[3],
        "timestamp_accuracy": fields[4],
        "snaplen": fields[5],
        "link_layer_type": fields[6],
    }

    while True:
        packet_header = f.read(16)
        if len(packet_header) < 16:
            break

        ph = struct.unpack("<IIII", packet_header)

        p_header = {
            "timestamp_sec": ph[0],
            "timestamp_microsec": ph[1],
            "caplen": ph[2],
            "orglen": ph[3],
        }

        packet = f.read(p_header["caplen"])
        temp = struct.unpack("<I", packet[:4])
        assert temp == 2  # make sure it's ipv4
        ihl = (packet[4] & 0x0F) << 2

        tcp_packet = f.read(ihl)
