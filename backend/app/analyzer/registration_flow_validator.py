from typing import Any


EXPECTED_NODES = {
    "P-CSCF",
    "S-CSCF",
}


def validate_registration_flow(
    packets,
    registration_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate IMS registration using observed SIP packets
    and node hints.

    This validator reports observed evidence. It does not
    assume that every deployment exposes every IMS node
    in the SIP headers.
    """

    observed_nodes = set()

    node_evidence = []

    for packet in packets:

        headers = [
            packet.from_header,
            packet.to_header,
            packet.via,
            packet.contact,
        ]

        packet_nodes = set()

        for header in headers:

            if not header:
                continue

            value = header.upper()

            if "P-CSCF" in value or "PCSCF" in value:
                packet_nodes.add("P-CSCF")

            if "S-CSCF" in value or "SCSCF" in value:
                packet_nodes.add("S-CSCF")

            if "I-CSCF" in value or "ICSCF" in value:
                packet_nodes.add("I-CSCF")

            if "TAS" in value:
                packet_nodes.add("TAS")

            if "IBCF" in value:
                packet_nodes.add("IBCF")

        if packet_nodes:

            observed_nodes.update(packet_nodes)

            node_evidence.append({
                "frame": packet.frame_number,
                "nodes": sorted(packet_nodes),
            })

    # --------------------------------------------------
    # Determine registration state
    # --------------------------------------------------

    registration_passed = (
        registration_result.get("result") == "PASS"
    )

    has_pcscf = "P-CSCF" in observed_nodes
    has_scscf = "S-CSCF" in observed_nodes

    has_icscf = "I-CSCF" in observed_nodes

    # --------------------------------------------------
    # Build checks
    # --------------------------------------------------

    checks = []

    checks.append({
        "check": "REGISTER detected",
        "passed": (
            registration_result.get("register_count", 0) > 0
        ),
    })

    checks.append({
        "check": "P-CSCF evidence detected",
        "passed": has_pcscf,
    })

    checks.append({
        "check": "S-CSCF evidence detected",
        "passed": has_scscf,
    })

    checks.append({
        "check": "I-CSCF evidence detected",
        "passed": has_icscf,
        "note": (
            "I-CSCF was not observed in the inspected SIP "
            "headers."
            if not has_icscf
            else "I-CSCF evidence observed."
        ),
    })

    checks.append({
        "check": "Registration completed",
        "passed": registration_passed,
    })

    # --------------------------------------------------
    # Important:
    # Missing I-CSCF is NOT automatically a failure.
    # --------------------------------------------------

    if registration_passed and has_pcscf and has_scscf:

        result = "PASS"

        reason = (
            "Registration completed successfully and "
            "P-CSCF/S-CSCF evidence was observed in the "
            "captured SIP signaling."
        )

    elif not registration_passed:

        result = "FAIL"

        reason = (
            "Registration did not complete successfully. "
            "Inspect the registration failure and root-cause "
            "evidence."
        )

    else:

        result = "INCOMPLETE"

        reason = (
            "Registration result could not be fully correlated "
            "with the expected IMS node evidence."
        )

    return {
        "test": "IMS Registration Flow",
        "result": result,
        "reason": reason,
        "observed_nodes": sorted(observed_nodes),
        "checks": checks,
        "node_evidence": node_evidence,
    }


if __name__ == "__main__":

    print()
    print("=" * 70)
    print("IMS REGISTRATION FLOW VALIDATOR")
    print("=" * 70)
    print()
    print("This module is intended to be called")
    print("from the main validation pipeline.")
    print()
