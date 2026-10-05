from typing import Any


# SIP response interpretation for IMS validation.
#
# These are evidence-based investigation hints.
# The engine should not claim a definitive root cause
# unless the packet evidence proves it.


SIP_FAILURE_RULES = {
    400: {
        "category": "Malformed Request",
        "likely_area": "SIP request formatting",
        "action": "Inspect the REGISTER request headers, URI and SIP syntax.",
    },
    401: {
        "category": "Authentication Challenge",
        "likely_area": "IMS authentication",
        "action": (
            "Expected during IMS AKA registration. "
            "Check whether a subsequent authenticated REGISTER "
            "is received."
        ),
    },
    403: {
        "category": "Authorization / Provisioning",
        "likely_area": "Subscriber authorization or provisioning",
        "action": (
            "Check subscriber provisioning, authentication state, "
            "service authorization and related HSS/Cx transactions."
        ),
    },
    404: {
        "category": "User / Routing Not Found",
        "likely_area": "Subscriber addressing or routing",
        "action": (
            "Check the Request-URI, subscriber identity and "
            "IMS routing configuration."
        ),
    },
    408: {
        "category": "Request Timeout",
        "likely_area": "Network response / downstream node",
        "action": (
            "Check whether the expected downstream IMS node "
            "responded and inspect packet timing."
        ),
    },
    480: {
        "category": "Temporarily Unavailable",
        "likely_area": "Subscriber availability",
        "action": (
            "Check registration state and whether the subscriber "
            "is currently reachable."
        ),
    },
    481: {
        "category": "Transaction / Dialog Not Found",
        "likely_area": "SIP transaction or dialog correlation",
        "action": (
            "Check Call-ID, tags, CSeq and transaction/dialog "
            "state between IMS nodes."
        ),
    },
    484: {
        "category": "Address Incomplete",
        "likely_area": "Destination addressing",
        "action": (
            "Inspect the Request-URI and destination number/address."
        ),
    },
    486: {
        "category": "Busy Here",
        "likely_area": "Destination subscriber",
        "action": "Check terminating subscriber availability.",
    },
    500: {
        "category": "Server Error",
        "likely_area": "IMS server",
        "action": (
            "Identify the responding IMS node and inspect its "
            "application/server logs."
        ),
    },
    503: {
        "category": "Service Unavailable",
        "likely_area": "IMS service / node availability",
        "action": (
            "Check the responding node, service availability, "
            "overload state and downstream connectivity."
        ),
    },
    504: {
        "category": "Server Timeout",
        "likely_area": "Downstream IMS node",
        "action": (
            "Check communication with the downstream node and "
            "look for delayed or missing responses."
        ),
    },
    600: {
        "category": "Busy Everywhere",
        "likely_area": "Destination subscriber",
        "action": "Check terminating subscriber state.",
    },
}


def get_sip_failure_rule(status_code: int) -> dict[str, str]:
    """
    Return the investigation rule for a SIP response code.
    """

    return SIP_FAILURE_RULES.get(
        status_code,
        {
            "category": "SIP Failure",
            "likely_area": "IMS signaling",
            "action": (
                "Inspect the SIP response, transaction and "
                "adjacent IMS signaling."
            ),
        },
    )


def analyze_failure(failure: dict[str, Any] | None) -> dict[str, Any] | None:
    """
    Convert a detected registration failure into a
    structured root-cause investigation result.
    """

    if not failure:
        return None

    status_code = failure.get("status_code")

    if status_code is None:
        return {
            "severity": "ERROR",
            "category": "Unknown SIP Failure",
            "evidence": failure,
            "likely_area": "IMS signaling",
            "action": "Inspect the failed SIP transaction.",
        }

    rule = get_sip_failure_rule(int(status_code))

    return {
        "severity": "ERROR",
        "status_code": int(status_code),
        "category": rule["category"],
        "likely_area": rule["likely_area"],
        "frame": failure.get("frame_number"),
        "time": failure.get("time_relative"),
        "source": failure.get("source"),
        "destination": failure.get("destination"),
        "status_line": failure.get("status_line"),
        "call_id": failure.get("call_id"),
        "cseq": failure.get("cseq"),
        "evidence": (
            f"SIP {status_code} response observed "
            f"at frame {failure.get('frame_number')}."
        ),
        "recommended_action": rule["action"],
    }


def analyze_registration_root_cause(
    registration_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze the output of registration_analyzer.py
    and generate root-cause information.
    """

    sessions = registration_result.get("sessions", [])

    analyzed_sessions = []

    for session in sessions:

        failure = session.get("failure")

        root_cause = analyze_failure(failure)

        session_result = {
            "subscriber": session.get("subscriber"),
            "result": session.get("result"),
            "reason": session.get("reason"),
            "root_cause": root_cause,
        }

        analyzed_sessions.append(session_result)

    failures = [
        session
        for session in analyzed_sessions
        if session["root_cause"] is not None
    ]

    return {
        "test": registration_result.get(
            "test",
            "IMS Registration",
        ),
        "result": registration_result.get("result"),
        "reason": registration_result.get("reason"),
        "total_sessions": len(analyzed_sessions),
        "failed_sessions": len(failures),
        "sessions": analyzed_sessions,
    }


if __name__ == "__main__":

    # Small standalone test
    sample_failure = {
        "status_code": 403,
        "frame_number": "12345",
        "time_relative": "12.345",
        "source": "172.27.71.164",
        "destination": "10.244.10.234",
        "status_line": "SIP/2.0 403 Forbidden",
        "call_id": "example-call-id",
        "cseq": "2 REGISTER",
    }

    result = analyze_failure(sample_failure)

    print()
    print("=" * 70)
    print("IMS ROOT CAUSE ENGINE")
    print("=" * 70)

    for key, value in result.items():
        print(f"{key}: {value}")

    print("=" * 70)
