import csv
import io
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class SipPacket:
    frame_number: str
    time_relative: str
    source: str
    destination: str
    method: Optional[str]
    status_code: Optional[str]
    call_id: Optional[str]
    cseq: Optional[str]
    request_line: Optional[str]
    status_line: Optional[str]
    from_header: Optional[str]
    to_header: Optional[str]
    contact: Optional[str]
    via: Optional[str]

    # Complete SIP message information
    sip_headers: Optional[str]
    sip_body: Optional[str]


def analyze_pcap(pcap_file: str) -> list[SipPacket]:
    """
    Read SIP packets from a PCAP/PCAPNG file using tshark.

    Returns:
        list[SipPacket]: Parsed SIP packets.
    """

    command = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "sip",
        "-T",
        "fields",

        "-E",
        "separator=\t",

        "-E",
        "quote=d",

        "-E",
        "occurrence=f",

        # Basic packet information
        "-e",
        "frame.number",

        "-e",
        "frame.time_relative",

        "-e",
        "ip.src",

        "-e",
        "ip.dst",

        # SIP information
        "-e",
        "sip.Method",

        "-e",
        "sip.Status-Code",

        "-e",
        "sip.Call-ID",

        "-e",
        "sip.CSeq",

        "-e",
        "sip.Request-Line",

        "-e",
        "sip.Status-Line",

        # Headers useful for IMS correlation
        "-e",
        "sip.From",

        "-e",
        "sip.To",

        "-e",
        "sip.Contact",

        "-e",
        "sip.Via",

        # Complete SIP headers
        "-e",
        "sip.msg_hdr",

        # SIP message body
        "-e",
        "sip.msg_body",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )

    except FileNotFoundError:
        raise RuntimeError(
            "tshark was not found. "
            "Please install Wireshark/TShark."
        )

    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"tshark failed:\n{error.stderr}"
        )

    packets: list[SipPacket] = []

    reader = csv.reader(
        io.StringIO(result.stdout),
        delimiter="\t",
        quotechar='"',
    )

    for row in reader:

        # We now expect 16 fields.
        # Add empty values if tshark omitted fields.
        row += [""] * (16 - len(row))

        packet = SipPacket(
            frame_number=row[0],
            time_relative=row[1],
            source=row[2],
            destination=row[3],
            method=row[4] or None,
            status_code=row[5] or None,
            call_id=row[6] or None,
            cseq=row[7] or None,
            request_line=row[8] or None,
            status_line=row[9] or None,
            from_header=row[10] or None,
            to_header=row[11] or None,
            contact=row[12] or None,
            via=row[13] or None,

            sip_headers=row[14] or None,
            sip_body=row[15] or None,
        )

        packets.append(packet)

    return packets


def print_packet(packet: SipPacket) -> None:
    """
    Print a SIP packet in a readable format.
    """

    print("=" * 70)

    print(f"Frame       : {packet.frame_number}")
    print(f"Time        : {packet.time_relative}")
    print(f"Source      : {packet.source}")
    print(f"Destination : {packet.destination}")
    print(f"Method      : {packet.method}")
    print(f"Status Code : {packet.status_code}")
    print(f"Call-ID     : {packet.call_id}")
    print(f"CSeq        : {packet.cseq}")

    print(f"Request     : {packet.request_line}")
    print(f"Status      : {packet.status_line}")

    print(f"From        : {packet.from_header}")
    print(f"To          : {packet.to_header}")
    print(f"Contact     : {packet.contact}")
    print(f"Via         : {packet.via}")

    print()
    print("SIP Headers:")
    print("-" * 70)
    print(packet.sip_headers or "No SIP headers available")

    if packet.sip_body:
        print()
        print("SIP Body:")
        print("-" * 70)
        print(packet.sip_body)


if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:
        print()
        print("Usage:")
        print(
            "python3 backend/app/analyzer/pcap_analyzer.py "
            "<capture.pcapng>"
        )
        print()
        sys.exit(1)

    pcap_file = sys.argv[1]

    print()
    print("=" * 70)
    print("              IMS PCAP ANALYZER")
    print("=" * 70)
    print()

    print(f"PCAP file: {pcap_file}")
    print()

    try:

        packets = analyze_pcap(pcap_file)

        print(f"Total SIP packets: {len(packets)}")
        print()

        # Display first 10 packets
        for packet in packets[:10]:
            print_packet(packet)

        print()
        print("=" * 70)
        print(
            f"Displayed first {min(10, len(packets))} "
            f"of {len(packets)} SIP packets."
        )
        print("=" * 70)

    except Exception as error:

        print()
        print("ERROR")
        print("-" * 70)
        print(error)
        print()

        sys.exit(1)
