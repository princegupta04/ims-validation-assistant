from typing import Any


IMS_NODE_NAMES = {
    "P-CSCF": [
        "P-CSCF",
        "PCSCF",
        "IMS_PCSCF",
    ],
    "I-CSCF": [
        "I-CSCF",
        "ICSCF",
        "IMS_ICSCF",
    ],
    "S-CSCF": [
        "S-CSCF",
        "SCSCF",
        "IMS_SCSCF",
    ],
    "TAS": [
        "TAS",
        "IMS_TAS",
    ],
    "IBCF": [
        "IBCF",
        "IMS_IBCF",
    ],
}


def identify_node_from_text(text: str | None) -> str | None:
    """
    Identify an IMS node from SIP header text.

    This is intentionally evidence-based. We only identify
    a node when its name appears in the captured SIP data.
    """

    if not text:
        return None

    text_upper = text.upper()

    for node_name, aliases in IMS_NODE_NAMES.items():

        for alias in aliases:

            if alias.upper() in text_upper:
                return node_name

    return None


def identify_packet_nodes(packet) -> dict[str, Any]:
    """
    Inspect SIP headers and return node hints.
    """

    headers = {
        "from": packet.from_header,
        "to": packet.to_header,
        "contact": packet.contact,
        "via": packet.via,
    }

    detected_nodes = []

    evidence = []

    for header_name, value in headers.items():

        node = identify_node_from_text(value)

        if node and node not in detected_nodes:

            detected_nodes.append(node)

            evidence.append({
                "header": header_name,
                "node": node,
                "value": value,
            })

    return {
        "nodes": detected_nodes,
        "evidence": evidence,
    }


def enrich_packet(packet) -> dict[str, Any]:
    """
    Add IMS node information to a parsed SIP packet.
    """

    node_info = identify_packet_nodes(packet)

    return {
        "frame": packet.frame_number,
        "source": packet.source,
        "destination": packet.destination,
        "method": packet.method,
        "status_code": packet.status_code,
        "call_id": packet.call_id,
        "nodes": node_info["nodes"],
        "node_evidence": node_info["evidence"],
    }


if __name__ == "__main__":

    print()
    print("=" * 70)
    print("IMS NODE IDENTIFIER")
    print("=" * 70)
    print()

    print("Supported node hints:")
    print()

    for node in IMS_NODE_NAMES:
        print(f"  - {node}")

    print()
