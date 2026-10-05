def _get(data, key, default=None):
    if isinstance(data, dict):
        return data.get(key, default)
    return getattr(data, key, default)


def _result(value):
    return str(value or "UNKNOWN").upper()


def generate_validation_report(
    registration,
    root_cause,
    registration_flow,
    call_validation,
    diameter,
):
    """
    Convert raw analyzer output into an engineer-friendly
    IMS validation report.
    """

    registration_result = _result(
        _get(registration, "result")
    )

    flow_result = _result(
        _get(registration_flow, "result")
    )

    call_result = _result(
        _get(call_validation, "result")
    )

    diameter_result = "UNKNOWN"

    if isinstance(diameter, dict):
        failed_transactions = diameter.get("failed_transactions", 0)
        unknown_transactions = diameter.get("unknown_transactions", 0)

        if failed_transactions > 0:
            diameter_result = "FAIL"
        elif unknown_transactions > 0:
            diameter_result = "INCOMPLETE"
        else:
            diameter_result = "PASS"

    # ---------------------------------------------------------
    # Registration
    # ---------------------------------------------------------

    registration_report = {
        "result": registration_result,
        "sessions": _get(registration, "session_count", 0),
        "successful": _get(registration, "successful_sessions", 0),
        "failed": _get(registration, "failed_sessions", 0),
        "incomplete": _get(registration, "incomplete_sessions", 0),
        "reason": _get(registration, "reason", ""),
    }

    # ---------------------------------------------------------
    # Registration Flow
    # ---------------------------------------------------------

    flow_checks = _get(registration_flow, "checks", [])

    if isinstance(flow_checks, dict):
        checks = flow_checks
    else:
        checks = {}

        for check in flow_checks or []:
            if isinstance(check, dict):
                name = check.get("check")
                result = check.get("result")

                if name:
                    checks[name] = result

    node_evidence = _get(
        registration_flow,
        "node_evidence",
        {},
    )
    node_text = " ".join(
       str(item)
       for item in node_evidence
    )
    registration_flow_report = {
        "result": flow_result,
        "pcscf": "P-CSCF" in node_text,
        "icscf": "I-CSCF" in node_text,
        "scscf": "S-CSCF" in node_text,
        "registration_completed": (
            registration_result == "PASS"
        ),
        "checks": checks,
    }

    # ---------------------------------------------------------
    # Calls
    # ---------------------------------------------------------

    call_report = {
        "result": call_result,
        "calls": _get(call_validation, "call_count", 0),
        "successful": _get(
            call_validation,
            "successful_calls",
            0,
        ),
        "failed": _get(
            call_validation,
            "failed_calls",
            0,
        ),
        "incomplete": _get(
            call_validation,
            "incomplete_calls",
            0,
        ),
        "reason": _get(call_validation, "reason", ""),
    }

    # ---------------------------------------------------------
    # Diameter
    # ---------------------------------------------------------

    diameter_report = {
        "result": diameter_result,
        "transactions": _get(
            diameter,
            "transaction_count",
            _get(diameter, "transactions", 0),
        ),
        "successful": _get(
            diameter,
            "successful_transactions",
            0,
        ),
        "failed": _get(
            diameter,
            "failed_transactions",
            0,
        ),
        "unknown": _get(
            diameter,
            "unknown_transactions",
            0,
        ),
        "cx": "NOT OBSERVED",
    }

    if isinstance(diameter, dict):
        accounting = diameter.get("accounting", {})

        diameter_report["accounting"] = accounting.get(
            "total_transactions",
            0,
        )

        diameter_report["pcscf_nodes"] = accounting.get(
            "pcscf_nodes",
            {},
        )

    # ---------------------------------------------------------
    # Overall result
    # ---------------------------------------------------------

    results = [
        registration_result,
        flow_result,
        call_result,
        diameter_result,
    ]

    if "FAIL" in results:
        overall_result = "FAIL"
    elif "INCOMPLETE" in results or "UNKNOWN" in results:
        overall_result = "INCOMPLETE"
    else:
        overall_result = "PASS"

    return {
        "result": overall_result,
        "registration": registration_report,
        "registration_flow": registration_flow_report,
        "calls": call_report,
        "diameter": diameter_report,
        "root_cause": root_cause,
    }


def print_validation_report(report):
    """
    Print an engineer-friendly validation report.
    """

    registration = report["registration"]
    flow = report["registration_flow"]
    calls = report["calls"]
    diameter = report["diameter"]

    print()
    print("=" * 64)
    print("                 IMS VALIDATION REPORT")
    print("=" * 64)

    # ---------------------------------------------------------
    # Registration
    # ---------------------------------------------------------

    print()
    print("IMS REGISTRATION")
    print("-" * 64)

    print(f"Result            : {registration['result']}")
    print(f"Sessions           : {registration['sessions']}")
    print(f"Successful         : {registration['successful']}")
    print(f"Failed             : {registration['failed']}")
    print(f"Incomplete         : {registration['incomplete']}")

    if registration["reason"]:
        print(f"Reason             : {registration['reason']}")

    # ---------------------------------------------------------
    # Signaling Flow
    # ---------------------------------------------------------

    print()
    print("IMS SIGNALING FLOW")
    print("-" * 64)

    print(f"Result             : {flow['result']}")
    print(
        f"P-CSCF             : "
        f"{'DETECTED' if flow['pcscf'] else 'NOT OBSERVED'}"
    )
    print(
        f"I-CSCF             : "
        f"{'DETECTED' if flow['icscf'] else 'NOT OBSERVED'}"
    )
    print(
        f"S-CSCF             : "
        f"{'DETECTED' if flow['scscf'] else 'NOT OBSERVED'}"
    )
    print(
        f"Registration       : "
        f"{'COMPLETED' if flow['registration_completed'] else 'NOT COMPLETED'}"
    )

    # ---------------------------------------------------------
    # Calls
    # ---------------------------------------------------------

    print()
    print("IMS CALL VALIDATION")
    print("-" * 64)

    print(f"Result             : {calls['result']}")
    print(f"Calls              : {calls['calls']}")
    print(f"Successful         : {calls['successful']}")
    print(f"Failed             : {calls['failed']}")
    print(f"Incomplete         : {calls['incomplete']}")

    # ---------------------------------------------------------
    # Diameter
    # ---------------------------------------------------------

    print()
    print("DIAMETER")
    print("-" * 64)

    print(f"Result             : {diameter['result']}")
    print(f"Transactions       : {diameter['transactions']}")
    print(f"Successful         : {diameter['successful']}")
    print(f"Failed             : {diameter['failed']}")
    print(f"Unknown            : {diameter['unknown']}")
    print(f"Cx                 : {diameter['cx']}")
    print(f"Accounting         : {diameter.get('accounting', 0)}")

    # ---------------------------------------------------------
    # P-CSCF Diameter nodes
    # ---------------------------------------------------------

    nodes = diameter.get("pcscf_nodes", {})

    if nodes:
        print()
        print("P-CSCF DIAMETER NODES")
        print("-" * 64)

        for node, stats in nodes.items():
            print()
            print(node)
            print(f"  Transactions : {stats.get('transactions', 0)}")
            print(f"  Successful   : {stats.get('successful', 0)}")
            print(f"  Failed       : {stats.get('failed', 0)}")

    # ---------------------------------------------------------
    # Overall
    # ---------------------------------------------------------

    print()
    print("=" * 64)
    print("OVERALL RESULT")
    print("-" * 64)
    print(report["result"])
    print("=" * 64)
