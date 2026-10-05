from typing import Any


def parse_cseq(cseq: str | None):
    """
    Parse SIP CSeq.

    Example:
        '1 REGISTER' -> (1, 'REGISTER')
    """

    if not cseq:
        return None, None

    parts = cseq.strip().split()

    if len(parts) < 2:
        return None, None

    try:
        number = int(parts[0])
    except ValueError:
        return None, parts[1].upper()

    return number, parts[1].upper()


def extract_subscriber(from_header: str | None) -> str:
    """
    Extract subscriber identity from SIP From header.
    """

    if not from_header:
        return "UNKNOWN"

    value = from_header

    if "<sip:" in value:
        value = value.split("<sip:", 1)[1]

    elif "<tel:" in value:
        value = value.split("<tel:", 1)[1]

    value = value.split("@", 1)[0]
    value = value.split(";", 1)[0]
    value = value.split(">", 1)[0]

    return value


def get_response_packets(
    packets,
    call_id: str | None,
    cseq_number: int,
):
    """
    Find SIP responses belonging to a particular
    Call-ID + CSeq transaction.
    """

    responses = []

    for packet in packets:

        if not packet.status_code:
            continue

        if packet.call_id != call_id:
            continue

        packet_cseq, packet_method = parse_cseq(packet.cseq)

        if packet_cseq != cseq_number:
            continue

        if packet_method != "REGISTER":
            continue

        responses.append(packet)

    return responses


def build_event(packet, event_type: str) -> dict[str, Any]:
    """
    Convert a SIP packet into a GUI-friendly timeline event.
    """

    cseq_number, cseq_method = parse_cseq(packet.cseq)

    return {
        "frame": packet.frame_number,
        "time": packet.time_relative,
        "source": packet.source,
        "destination": packet.destination,
        "event": event_type,
        "method": packet.method,
        "status_code": packet.status_code,
        "call_id": packet.call_id,
        "cseq": cseq_number,
        "cseq_method": cseq_method,
        "status_line": packet.status_line,

        # Complete SIP message information for packet-level
        # investigation in the frontend.
        "sip_headers": packet.sip_headers,
        "sip_body": packet.sip_body,
    }


def analyze_registration_session(
    subscriber: str,
    requests,
    packets,
) -> dict[str, Any]:
    """
    Analyze one subscriber's registration sequence.

    Expected sequence:

        REGISTER
            |
            +--> 401
            |
        REGISTER
            |
            +--> 200 OK
    """

    # ---------------------------------------------------------
    # Parse REGISTER requests
    # ---------------------------------------------------------

    parsed_requests = []

    for packet in requests:

        cseq_number, cseq_method = parse_cseq(packet.cseq)

        if cseq_number is None:
            continue

        if cseq_method != "REGISTER":
            continue

        parsed_requests.append({
            "packet": packet,
            "cseq": cseq_number,
        })

    if not parsed_requests:

        return {
            "subscriber": subscriber,
            "result": "INCOMPLETE",
            "reason": "No valid REGISTER CSeq found.",
            "timeline": [],
            "initial_cseq": None,
            "authenticated_cseq": None,
            "authentication_challenge": False,
            "failure": None,
        }

    # ---------------------------------------------------------
    # Sort by CSeq and time
    # ---------------------------------------------------------

    parsed_requests.sort(
        key=lambda item: (
            item["cseq"],
            float(item["packet"].time_relative or 0),
        )
    )

    # ---------------------------------------------------------
    # Remove duplicate captured copies of the same
    # Call-ID + CSeq + source + destination combination.
    # ---------------------------------------------------------

    unique_requests = []
    seen = set()

    for item in parsed_requests:

        packet = item["packet"]

        key = (
            packet.call_id,
            item["cseq"],
            packet.source,
            packet.destination,
        )

        if key in seen:
            continue

        seen.add(key)
        unique_requests.append(item)

    # ---------------------------------------------------------
    # Timeline
    # ---------------------------------------------------------

    timeline = []

    initial_cseq = None
    authenticated_cseq = None
    authentication_challenge = False
    failure = None

    # ---------------------------------------------------------
    # Analyze each REGISTER
    # ---------------------------------------------------------

    for index, item in enumerate(unique_requests):

        packet = item["packet"]
        cseq = item["cseq"]

        if initial_cseq is None:
            initial_cseq = cseq

        # Add REGISTER event
        timeline.append(
            build_event(
                packet,
                "REGISTER",
            )
        )

        responses = get_response_packets(
            packets,
            packet.call_id,
            cseq,
        )

        # Remove duplicate response observations
        unique_responses = []
        response_seen = set()

        for response in responses:

            key = (
                response.frame_number,
                response.status_code,
                response.source,
                response.destination,
            )

            if key in response_seen:
                continue

            response_seen.add(key)
            unique_responses.append(response)

        # -----------------------------------------------------
        # Process responses
        # -----------------------------------------------------

        for response in unique_responses:

            status = int(response.status_code)

            if status == 100:

                timeline.append(
                    build_event(
                        response,
                        "100 TRYING",
                    )
                )

            elif status == 401:

                authentication_challenge = True

                timeline.append(
                    build_event(
                        response,
                        "401 AUTHENTICATION CHALLENGE",
                    )
                )

            elif 200 <= status < 300:

                timeline.append(
                    build_event(
                        response,
                        f"{status} SUCCESS",
                    )
                )

            elif 400 <= status <= 699:

                # 401 is expected during IMS authentication.
                if status != 401:

                    if failure is None:

                        failure = {
                            "status_code": status,
                            "frame_number": response.frame_number,
                            "time_relative": response.time_relative,
                            "source": response.source,
                            "destination": response.destination,
                            "status_line": response.status_line,
                            "call_id": response.call_id,
                            "cseq": response.cseq,
                        }

                    timeline.append(
                        build_event(
                            response,
                            f"{status} FAILURE",
                        )
                    )

    # ---------------------------------------------------------
    # Determine authenticated CSeq
    # ---------------------------------------------------------

    if authentication_challenge:

        for item in unique_requests:

            if (
                initial_cseq is not None
                and item["cseq"] > initial_cseq
            ):
                authenticated_cseq = item["cseq"]
                break

    # ---------------------------------------------------------
    # Determine successful registration
    # ---------------------------------------------------------

    success_events = [
        event
        for event in timeline
        if event["event"] == "200 SUCCESS"
    ]

    # ---------------------------------------------------------
    # Determine result
    # ---------------------------------------------------------

    if failure is not None:

        result = "FAIL"

        reason = (
            f"Registration failed with SIP "
            f"{failure['status_code']} at frame "
            f"{failure['frame_number']}."
        )

    elif authentication_challenge and authenticated_cseq is not None:

        if success_events:

            result = "PASS"

            reason = (
                "REGISTER received a 401 authentication "
                "challenge, followed by a subsequent REGISTER "
                "and successful 200 OK."
            )

        else:

            result = "INCOMPLETE"

            reason = (
                "Authentication challenge was received and a "
                "subsequent REGISTER was observed, but no "
                "successful 200 OK was found."
            )

    elif success_events:

        result = "PASS"

        reason = (
            "REGISTER received a successful 200 OK."
        )

    else:

        result = "INCOMPLETE"

        reason = (
            "REGISTER was observed but registration did not "
            "reach a successful final response."
        )

    return {
        "subscriber": subscriber,
        "result": result,
        "reason": reason,
        "initial_cseq": initial_cseq,
        "authenticated_cseq": authenticated_cseq,
        "authentication_challenge": authentication_challenge,
        "failure": failure,
        "timeline": timeline,
    }


def analyze_registration(packets) -> dict[str, Any]:
    """
    Analyze all IMS registration sessions in a PCAP.
    """

    register_requests = [
        packet
        for packet in packets
        if packet.method == "REGISTER"
    ]

    if not register_requests:

        return {
            "test": "IMS Registration",
            "result": "NOT_FOUND",
            "reason": "No SIP REGISTER request was found.",
            "register_count": 0,
            "session_count": 0,
            "successful_sessions": 0,
            "failed_sessions": 0,
            "incomplete_sessions": 0,
            "sessions": [],
        }

    # ---------------------------------------------------------
    # Group REGISTER requests by subscriber
    # ---------------------------------------------------------

    subscriber_groups = {}

    for packet in register_requests:

        subscriber = extract_subscriber(
            packet.from_header
        )

        if subscriber not in subscriber_groups:
            subscriber_groups[subscriber] = []

        subscriber_groups[subscriber].append(packet)

    sessions = []

    # ---------------------------------------------------------
    # Analyze every subscriber
    # ---------------------------------------------------------

    for subscriber, requests in subscriber_groups.items():

        session = analyze_registration_session(
            subscriber,
            requests,
            packets,
        )

        sessions.append(session)

    # ---------------------------------------------------------
    # Overall statistics
    # ---------------------------------------------------------

    successful_sessions = [
        session
        for session in sessions
        if session["result"] == "PASS"
    ]

    failed_sessions = [
        session
        for session in sessions
        if session["result"] == "FAIL"
    ]

    incomplete_sessions = [
        session
        for session in sessions
        if session["result"] == "INCOMPLETE"
    ]

    # ---------------------------------------------------------
    # Overall result
    # ---------------------------------------------------------

    if failed_sessions:

        result = "FAIL"

        first_failure = failed_sessions[0]["failure"]

        reason = (
            f"Registration failure detected at frame "
            f"{first_failure['frame_number']} "
            f"with SIP {first_failure['status_code']}."
        )

    elif successful_sessions:

        result = "PASS"

        reason = (
            f"{len(successful_sessions)} registration "
            "session(s) completed successfully."
        )

    else:

        result = "INCOMPLETE"

        reason = (
            "REGISTER requests were detected, but no "
            "successful registration session was completed."
        )

    return {
        "test": "IMS Registration",
        "result": result,
        "reason": reason,
        "register_count": len(register_requests),
        "session_count": len(sessions),
        "successful_sessions": len(successful_sessions),
        "failed_sessions": len(failed_sessions),
        "incomplete_sessions": len(incomplete_sessions),
        "sessions": sessions,
    }
