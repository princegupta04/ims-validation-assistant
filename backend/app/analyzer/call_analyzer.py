from dataclasses import asdict, is_dataclass


# ============================================================
# SIP RESPONSE / FAILURE DEFINITIONS
# ============================================================

FAILURE_CODES = {
    400: "Malformed Request",
    403: "Forbidden / Authorization Failure",
    404: "User / Routing Not Found",
    408: "Request Timeout",
    480: "Temporarily Unavailable",
    481: "Transaction / Dialog Does Not Exist",
    484: "Address Incomplete",
    486: "Busy Here",
    487: "Request Terminated",
    488: "Not Acceptable Here",
    500: "Server Internal Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Server Timeout",
    600: "Busy Everywhere",
    603: "Decline",
}


EXPECTED_RESPONSES = {
    100: "Trying",
    180: "Ringing",
    181: "Call Is Being Forwarded",
    182: "Queued",
    183: "Session Progress",
    200: "OK",
}


# ============================================================
# HELPERS
# ============================================================

def get_value(packet, field, default=None):
    """
    Safely read a field from SipPacket.
    Supports both dataclass objects and dictionaries.
    """

    if isinstance(packet, dict):
        return packet.get(field, default)

    return getattr(packet, field, default)


def packet_to_dict(packet):
    """
    Convert a packet/dataclass into a dictionary.
    """

    if is_dataclass(packet):
        return asdict(packet)

    if isinstance(packet, dict):
        return packet

    return {
        key: getattr(packet, key)
        for key in dir(packet)
        if not key.startswith("_")
        and not callable(getattr(packet, key))
    }


def parse_cseq(cseq):
    """
    Extract numeric CSeq value.

    Examples:
        '123 INVITE' -> 123
        '123 ACK'    -> 123
    """

    if not cseq:
        return None

    try:
        return int(str(cseq).split()[0])
    except (ValueError, IndexError):
        return None


def get_method(packet):
    method = get_value(packet, "method")

    if method:
        return str(method).upper().strip()

    request_line = get_value(
        packet,
        "request_line",
        ""
    )

    if request_line:
        return str(
            request_line
        ).split()[0].upper()

    return None


def get_status_code(packet):
    value = get_value(
        packet,
        "status_code"
    )

    if value in (None, ""):
        return None

    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def get_call_id(packet):
    value = get_value(
        packet,
        "call_id"
    )

    if value is None:
        return None

    return str(value).strip()


def get_time(packet):
    value = get_value(
        packet,
        "time_relative"
    )

    if value is None:
        return 0.0

    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


# ============================================================
# CALL EVENT
# ============================================================

def build_event(packet):
    method = get_method(packet)
    status_code = get_status_code(packet)

    if method:
        event_name = method

    elif status_code is not None:
        event_name = (
            f"{status_code} "
            f"{EXPECTED_RESPONSES.get(status_code, '')}"
        ).strip()

    else:
        event_name = "UNKNOWN"

    return {
        "frame": get_value(packet, "frame_number"),
        "time": get_time(packet),
        "event": event_name,
        "method": method,
        "status_code": status_code,
        "call_id": get_call_id(packet),
        "cseq": get_value(packet, "cseq"),
        "cseq_number": parse_cseq(
            get_value(packet, "cseq")
        ),
        "source": get_value(packet, "source"),
        "destination": get_value(packet, "destination"),
    }


# ============================================================
# CALL FAILURE
# ============================================================

def build_failure(packet):
    status_code = get_status_code(packet)

    if status_code not in FAILURE_CODES:
        return None

    return {
        "frame": get_value(packet, "frame_number"),
        "time": get_time(packet),
        "status_code": status_code,
        "reason": FAILURE_CODES[status_code],
        "status_line": get_value(
            packet,
            "status_line"
        ),
        "call_id": get_call_id(packet),
        "cseq": get_value(packet, "cseq"),
        "source": get_value(packet, "source"),
        "destination": get_value(packet, "destination"),
    }


# ============================================================
# SINGLE CALL ANALYSIS
# ============================================================

def analyze_call_session(call_id, packets):
    """
    Analyze one SIP call identified by Call-ID.
    """

    packets = sorted(
        packets,
        key=get_time
    )

    events = [
        build_event(packet)
        for packet in packets
    ]

    failures = []

    for packet in packets:

        failure = build_failure(packet)

        if failure:
            failures.append(failure)

    methods = [
        get_method(packet)
        for packet in packets
    ]

    methods = [
        method
        for method in methods
        if method
    ]

    status_codes = [
        get_status_code(packet)
        for packet in packets
    ]

    status_codes = [
        status
        for status in status_codes
        if status is not None
    ]

    # --------------------------------------------------------
    # Detect important signaling
    # --------------------------------------------------------

    has_invite = "INVITE" in methods
    has_ack = "ACK" in methods
    has_bye = "BYE" in methods
    has_prack = "PRACK" in methods
    has_update = "UPDATE" in methods

    has_183 = 183 in status_codes
    has_180 = 180 in status_codes
    has_200 = 200 in status_codes

    # --------------------------------------------------------
    # Determine call establishment
    # --------------------------------------------------------

    # Find final successful response to INVITE.
    invite_200 = None

    for packet in packets:

        if get_status_code(packet) != 200:
            continue

        cseq = str(
            get_value(packet, "cseq", "")
        ).upper()

        if "INVITE" in cseq:
            invite_200 = packet
            break

    # --------------------------------------------------------
    # Timing
    # --------------------------------------------------------

    invite_packet = None

    for packet in packets:

        if get_method(packet) == "INVITE":
            invite_packet = packet
            break

    invite_time = (
        get_time(invite_packet)
        if invite_packet
        else None
    )

    progress_packet = None

    for packet in packets:

        status = get_status_code(packet)

        if status in (180, 183):
            progress_packet = packet
            break

    progress_time = (
        get_time(progress_packet)
        if progress_packet
        else None
    )

    ok_time = (
        get_time(invite_200)
        if invite_200
        else None
    )

    call_setup_ms = None

    if invite_time is not None and ok_time is not None:
        call_setup_ms = round(
            (ok_time - invite_time) * 1000,
            3
        )

    progress_ms = None

    if invite_time is not None and progress_time is not None:
        progress_ms = round(
            (progress_time - invite_time) * 1000,
            3
        )

    # --------------------------------------------------------
    # Call result
    # --------------------------------------------------------

    if failures:

        result = "FAIL"

        primary_failure = failures[0]

        reason = (
            f"SIP {primary_failure['status_code']} "
            f"{primary_failure['reason']}"
        )

    elif invite_200 and has_ack:

        result = "PASS"

        reason = (
            "INVITE completed with 200 OK "
            "and ACK was observed."
        )

    elif invite_200:

        result = "INCOMPLETE"

        reason = (
            "INVITE received 200 OK, "
            "but ACK was not observed."
        )

    elif has_invite:

        result = "INCOMPLETE"

        reason = (
            "INVITE detected but successful "
            "call establishment was not observed."
        )

    else:

        result = "INCOMPLETE"

        reason = "No INVITE transaction found."

    # --------------------------------------------------------
    # Signaling checks
    # --------------------------------------------------------

    signaling = {
        "INVITE": has_invite,
        "100 Trying": 100 in status_codes,
        "180 Ringing": has_180,
        "183 Session Progress": has_183,
        "PRACK": has_prack,
        "UPDATE": has_update,
        "200 OK": invite_200 is not None,
        "ACK": has_ack,
        "BYE": has_bye,
    }

    return {
        "call_id": call_id,

        "result": result,

        "reason": reason,

        "packet_count": len(packets),

        "events": events,

        "signaling": signaling,

        "failures": failures,

        "timing": {
            "invite_to_progress_ms": progress_ms,
            "invite_to_200ok_ms": call_setup_ms,
        },

        "has_invite": has_invite,

        "has_200ok": invite_200 is not None,

        "has_ack": has_ack,

        "has_bye": has_bye,

        "has_prack": has_prack,

        "has_update": has_update,
    }


# ============================================================
# ALL CALLS
# ============================================================

def analyze_calls(sip_packets):
    """
    Analyze all SIP Call-IDs containing INVITE.
    """

    calls = {}

    # --------------------------------------------------------
    # Group packets by Call-ID
    # --------------------------------------------------------

    for packet in sip_packets:

        call_id = get_call_id(packet)

        if not call_id:
            continue

        if call_id not in calls:
            calls[call_id] = []

        calls[call_id].append(packet)

    # --------------------------------------------------------
    # Analyze only Call-IDs containing INVITE
    # --------------------------------------------------------

    analyzed_calls = []

    for call_id, packets in calls.items():

        has_invite = any(
            get_method(packet) == "INVITE"
            for packet in packets
        )

        if not has_invite:
            continue

        analyzed_calls.append(
            analyze_call_session(
                call_id,
                packets
            )
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    successful = sum(
        1
        for call in analyzed_calls
        if call["result"] == "PASS"
    )

    failed = sum(
        1
        for call in analyzed_calls
        if call["result"] == "FAIL"
    )

    incomplete = sum(
        1
        for call in analyzed_calls
        if call["result"] == "INCOMPLETE"
    )

    if failed > 0:

        overall_result = "FAIL"

        reason = (
            f"{failed} call(s) failed."
        )

    elif incomplete > 0:

        overall_result = "INCOMPLETE"

        reason = (
            f"{incomplete} call(s) incomplete."
        )

    elif successful > 0:

        overall_result = "PASS"

        reason = (
            f"{successful} call(s) completed successfully."
        )

    else:

        overall_result = "NOT_OBSERVED"

        reason = "No SIP INVITE calls detected."

    return {
        "test": "IMS Call Validation",

        "result": overall_result,

        "reason": reason,

        "call_count": len(analyzed_calls),

        "successful_calls": successful,

        "failed_calls": failed,

        "incomplete_calls": incomplete,

        "calls": analyzed_calls,
    }
