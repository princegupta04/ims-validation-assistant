import json
from dataclasses import asdict, is_dataclass

from pcap_analyzer import analyze_pcap
from registration_analyzer import analyze_registration
from root_cause_engine import analyze_registration_root_cause
from registration_flow_validator import validate_registration_flow
from call_analyzer import analyze_calls
from diameter_analyzer import analyze_diameter
from report_generator import (
    generate_validation_report,
    print_validation_report,
)


PCAP_FILE = "captures/registration.pcapng"


def make_json_serializable(obj):
    """
    Convert dataclasses and nested objects into
    JSON-serializable Python objects.
    """

    if is_dataclass(obj):
        return {
            key: make_json_serializable(value)
            for key, value in asdict(obj).items()
        }

    if isinstance(obj, dict):
        return {
            key: make_json_serializable(value)
            for key, value in obj.items()
        }

    if isinstance(obj, (list, tuple)):
        return [
            make_json_serializable(value)
            for value in obj
        ]

    return obj


def print_registration_summary(registration):

    print("\n" + "-" * 70)
    print("IMS REGISTRATION")
    print("-" * 70)

    print(f"Result             : {registration.get('result', 'UNKNOWN')}")
    print(f"Reason             : {registration.get('reason', '')}")
    print(f"REGISTER messages  : {registration.get('register_count', 0)}")
    print(f"Sessions           : {registration.get('session_count', 0)}")
    print(f"Successful         : {registration.get('successful_sessions', 0)}")
    print(f"Failed             : {registration.get('failed_sessions', 0)}")
    print(f"Incomplete         : {registration.get('incomplete_sessions', 0)}")


def print_root_cause_summary(root_cause):

    print("\n" + "-" * 70)
    print("ROOT CAUSE ANALYSIS")
    print("-" * 70)

    failures = root_cause.get("failures", [])

    if not failures:
        print("No SIP registration failures detected.")
        return

    print(f"Failures detected   : {len(failures)}")

    for failure in failures:

        print("\n" + "-" * 50)

        print(
            f"Subscriber          : "
            f"{failure.get('subscriber', 'UNKNOWN')}"
        )

        print(
            f"Severity            : "
            f"{failure.get('severity', 'UNKNOWN')}"
        )

        print(
            f"Status Code         : "
            f"{failure.get('status_code', 'UNKNOWN')}"
        )

        print(
            f"Category            : "
            f"{failure.get('category', 'UNKNOWN')}"
        )

        print(
            f"Likely Area         : "
            f"{failure.get('likely_area', 'UNKNOWN')}"
        )

        print(
            f"Evidence            : "
            f"{failure.get('evidence', '')}"
        )

        print(
            f"Recommended Action  : "
            f"{failure.get('recommended_action', '')}"
        )


def print_registration_flow_summary(flow):

    print("\n" + "-" * 70)
    print("IMS SIGNALING FLOW")
    print("-" * 70)

    print(
        f"Result              : "
        f"{flow.get('result', 'UNKNOWN')}"
    )

    print(
        f"Reason              : "
        f"{flow.get('reason', '')}"
    )

    print("\nChecks:")

    checks = flow.get("checks", [])

    if isinstance(checks, dict):

        for check_name, check_result in checks.items():

            print(
                f"  {check_name:<25}: "
                f"{check_result}"
            )

    elif isinstance(checks, list):

        for check in checks:

            if isinstance(check, dict):

                name = (
                    check.get("name")
                    or check.get("check")
                    or check.get("type")
                    or "Check"
                )

                result = (
                    check.get("result")
                    if "result" in check
                    else check.get("status")
                )

                if result is None:
                    result = check.get("message", check)

                print(
                    f"  {str(name):<25}: "
                    f"{result}"
                )

            else:

                print(f"  - {check}")

    else:

        print(f"  {checks}")

    nodes = flow.get("node_evidence", {})

    if nodes:

        print("\nObserved Nodes:")

        if isinstance(nodes, dict):

            for node, evidence in nodes.items():

                print(
                    f"  {node:<10}: "
                    f"{evidence}"
                )

        elif isinstance(nodes, list):

            for node in nodes:

                print(f"  - {node}")


def print_call_summary(call_validation):

    print("\n" + "-" * 70)
    print("IMS CALL VALIDATION")
    print("-" * 70)

    print(
        f"Result              : "
        f"{call_validation.get('result', 'UNKNOWN')}"
    )

    print(
        f"Reason              : "
        f"{call_validation.get('reason', '')}"
    )

    print(
        f"Calls               : "
        f"{call_validation.get('call_count', 0)}"
    )

    print(
        f"Successful          : "
        f"{call_validation.get('successful_calls', 0)}"
    )

    print(
        f"Failed              : "
        f"{call_validation.get('failed_calls', 0)}"
    )

    print(
        f"Incomplete          : "
        f"{call_validation.get('incomplete_calls', 0)}"
    )

    calls = call_validation.get("calls", [])

    if not calls:
        return

    print("\nCall Details:")

    for call in calls[:10]:

        print("\n" + "-" * 60)

        print(
            f"Call-ID             : "
            f"{call.get('call_id', 'UNKNOWN')}"
        )

        print(
            f"Result              : "
            f"{call.get('result', 'UNKNOWN')}"
        )

        print(
            f"Reason              : "
            f"{call.get('reason', '')}"
        )

        print(
            f"Packets             : "
            f"{call.get('packet_count', 0)}"
        )

        timing = call.get("timing", {})

        print(
            f"INVITE -> 200 OK    : "
            f"{timing.get('invite_to_200ok_ms')} ms"
        )

        signaling = call.get("signaling", {})

        if signaling:

            print("Signaling:")

            for name, value in signaling.items():

                print(
                    f"  {name:<22}: "
                    f"{'YES' if value else 'NO'}"
                )

        failures = call.get("failures", [])

        if failures:

            print("\nFailures:")

            for failure in failures:

                print(
                    f"  SIP {failure.get('status_code')} "
                    f"- {failure.get('reason')} "
                    f"(Frame {failure.get('frame')})"
                )


def print_diameter_summary(diameter):

    print("\n" + "-" * 70)
    print("DIAMETER ANALYSIS")
    print("-" * 70)

    print(
        f"Packets             : "
        f"{diameter.get('packet_count', 0)}"
    )

    print(
        f"Transactions        : "
        f"{diameter.get('transaction_count', 0)}"
    )

    print(
        f"Successful          : "
        f"{diameter.get('successful_transactions', 0)}"
    )

    print(
        f"Failed              : "
        f"{diameter.get('failed_transactions', 0)}"
    )

    print(
        f"Unknown             : "
        f"{diameter.get('unknown_transactions', 0)}"
    )

    print("\nDiameter Messages:")

    messages = diameter.get("message_summary", [])

    for message in messages:

        print(
            f"  {message.get('name', 'Unknown'):<22} "
            f"CMD {str(message.get('command_code', '')):<5} "
            f"APP {str(message.get('application_id', '')):<5} "
            f"Count {str(message.get('count', 0)):<5} "
            f"PASS {str(message.get('successful', 0)):<5} "
            f"FAIL {str(message.get('failed', 0)):<5}"
        )

    accounting = diameter.get("accounting", {})

    if accounting:

        print("\n" + "-" * 70)
        print("ACCOUNTING")
        print("-" * 70)

        print(
            f"Transactions       : "
            f"{accounting.get('total_transactions', 0)}"
        )

        print(
            f"Successful         : "
            f"{accounting.get('successful', 0)}"
        )

        print(
            f"Failed             : "
            f"{accounting.get('failed', 0)}"
        )

        print(
            f"Unknown            : "
            f"{accounting.get('unknown', 0)}"
        )

        record_types = accounting.get("record_types", {})

        if record_types:

            print("\nAccounting Record Types:")

            for record_type, count in record_types.items():

                print(
                    f"  {record_type:<12}: "
                    f"{count}"
                )

        nodes = accounting.get("pcscf_nodes", {})

        if nodes:

            print("\nP-CSCF Nodes:")

            for node, stats in nodes.items():

                print(f"\n  {node}")

                print(
                    f"    Transactions : "
                    f"{stats.get('transactions', 0)}"
                )

                print(
                    f"    Successful   : "
                    f"{stats.get('successful', 0)}"
                )

                print(
                    f"    Failed       : "
                    f"{stats.get('failed', 0)}"
                )

    health = diameter.get("health", {})

    if health:

        print("\n" + "-" * 70)
        print("DIAMETER HEALTH")
        print("-" * 70)

        watchdog = health.get(
            "device_watchdog",
            {}
        )

        accounting_health = health.get(
            "accounting",
            {}
        )

        cx = health.get(
            "cx",
            {}
        )

        if watchdog:

            print(
                f"Device-Watchdog    : "
                f"{watchdog.get('transactions', 0)} transactions | "
                f"{watchdog.get('successful', 0)} successful | "
                f"{watchdog.get('failed', 0)} failed"
            )

        if accounting_health:

            print(
                f"Accounting         : "
                f"{accounting_health.get('transactions', 0)} transactions | "
                f"{accounting_health.get('successful', 0)} successful | "
                f"{accounting_health.get('failed', 0)} failed"
            )

        if cx:

            print(
                f"IMS Cx             : "
                f"{cx.get('status', 'UNKNOWN')}"
            )


def main():

    print("=" * 70)
    print("IMS VALIDATION ASSISTANT")
    print("=" * 70)

    # ========================================================
    # STEP 1 - SIP PACKET PARSING
    # ========================================================

    print("\n[1/6] Parsing SIP packets...")

    sip_packets = analyze_pcap(
        PCAP_FILE
    )

    print(
        f"SIP packets parsed   : "
        f"{len(sip_packets)}"
    )

    # ========================================================
    # STEP 2 - IMS REGISTRATION
    # ========================================================

    print(
        "[2/6] Validating IMS registration..."
    )

    registration = analyze_registration(
        sip_packets
    )

    print_registration_summary(
        registration
    )

    # ========================================================
    # STEP 3 - ROOT CAUSE ANALYSIS
    # ========================================================

    print(
        "\n[3/6] Running root cause analysis..."
    )

    root_cause = analyze_registration_root_cause(
        registration
    )

    print_root_cause_summary(
        root_cause
    )

    # ========================================================
    # STEP 4 - IMS SIGNALING FLOW
    # ========================================================

    print(
        "\n[4/6] Validating IMS signaling flow..."
    )

    registration_flow = validate_registration_flow(
        sip_packets,
        registration
    )

    print_registration_flow_summary(
        registration_flow
    )

    # ========================================================
    # STEP 5 - IMS CALL VALIDATION
    # ========================================================

    print(
        "\n[5/6] Validating IMS calls..."
    )

    call_validation = analyze_calls(
        sip_packets
    )

    print_call_summary(
        call_validation
    )

    # ========================================================
    # STEP 6 - DIAMETER
    # ========================================================

    print(
        "\n[6/6] Analyzing Diameter traffic..."
    )

    diameter = analyze_diameter(
        PCAP_FILE
    )

    validation_report = generate_validation_report(
    registration,
    root_cause,
    registration_flow,
    call_validation,
    diameter,
    )

    print_validation_report(validation_report)

    print_diameter_summary(
        diameter
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "FINAL VALIDATION RESULT"
    )

    print(
        "=" * 70
    )

    registration_result = registration.get(
        "result",
        "UNKNOWN"
    )

    flow_result = registration_flow.get(
        "result",
        "UNKNOWN"
    )

    call_result = call_validation.get(
        "result",
        "NOT_OBSERVED"
    )

    diameter_failed = diameter.get(
        "failed_transactions",
        0
    )

    print(
        f"IMS Registration    : "
        f"{registration_result}"
    )

    print(
        f"IMS Signaling       : "
        f"{flow_result}"
    )

    print(
        f"IMS Calls           : "
        f"{call_result}"
    )

    if diameter_failed == 0:

        print(
            "Diameter            : HEALTHY"
        )

    else:

        print(
            f"Diameter            : "
            f"{diameter_failed} "
            f"FAILED TRANSACTION(S)"
        )

    # ========================================================
    # JSON REPORT
    # ========================================================

    report = {

        "pcap": PCAP_FILE,

        "registration": registration,

        "root_cause": root_cause,

        "registration_flow": registration_flow,

        "call_validation": call_validation,

        "diameter": diameter,
        
 "validation_report": validation_report,
    }

    print(
        "\n" + "=" * 70
    )

    print(
        "JSON REPORT"
    )

    print(
        "=" * 70
    )

    json_report = make_json_serializable(
        report
    )

    print(
        json.dumps(
            json_report,
            indent=2
        )
    )

    return json_report


if __name__ == "__main__":

    main()
