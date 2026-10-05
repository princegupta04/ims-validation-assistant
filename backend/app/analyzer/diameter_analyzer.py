import subprocess
import sys
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict


# ============================================================
# CONSTANTS
# ============================================================

ACCOUNTING_RECORD_TYPES = {
    1: "START",
    2: "INTERIM",
    3: "STOP",
    4: "EVENT",
}

DIAMETER_COMMANDS = {
    271: "Accounting",
    280: "Device-Watchdog",
}

DIAMETER_APPLICATIONS = {
    0: "Diameter Common Messages",
    3: "Diameter Base Accounting",
}

SUCCESS_RESULT_CODE = 2001


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class DiameterPacket:
    frame_number: int
    time_relative: float

    source: str | None
    destination: str | None

    command_code: int | None
    is_request: bool

    hop_by_hop_id: str | None

    answer_in: int | None
    answer_to: int | None

    response_time: float | None
    result_code: int | None

    application_id: int | None = None

    session_id: str | None = None
    user_name: str | None = None

    origin_host: str | None = None
    origin_realm: str | None = None

    destination_host: str | None = None
    destination_realm: str | None = None

    accounting_record_type: int | None = None
    accounting_record_number: int | None = None


@dataclass
class DiameterTransaction:
    request_frame: int
    answer_frame: int

    command_code: int | None
    command_name: str

    application_id: int | None
    application_name: str

    request_source: str | None
    request_destination: str | None

    answer_source: str | None
    answer_destination: str | None

    request_time: float
    answer_time: float

    latency_ms: float

    result_code: int | None
    result: str

    session_id: str | None

    origin_host: str | None

    accounting_record_type: int | None
    accounting_record_type_name: str | None

    accounting_record_number: int | None
    request_origin_host: str | None
    answer_origin_host: str | None

# ============================================================
# HELPERS
# ============================================================

def clean(value):
    """
    Clean TShark field output.
    """

    if value is None:
        return None

    value = value.strip().strip('"')

    if value == "":
        return None

    return value


def parse_int(value):
    value = clean(value)

    if value is None:
        return None

    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(value)
        except ValueError:
            return None


def parse_float(value):
    value = clean(value)

    if value is None:
        return None

    try:
        return float(value)
    except ValueError:
        return None


def command_name(command_code):
    if command_code is None:
        return "Unknown"

    return DIAMETER_COMMANDS.get(
        command_code,
        f"Command-{command_code}"
    )


def application_name(application_id):
    if application_id is None:
        return "Unknown"

    return DIAMETER_APPLICATIONS.get(
        application_id,
        f"Application-{application_id}"
    )


def accounting_type_name(record_type):
    if record_type is None:
        return None

    return ACCOUNTING_RECORD_TYPES.get(
        record_type,
        f"UNKNOWN-{record_type}"
    )


def result_status(result_code):
    """
    Diameter result-code classification.

    2001 = DIAMETER_SUCCESS
    """

    if result_code is None:
        return "UNKNOWN"

    if result_code == SUCCESS_RESULT_CODE:
        return "PASS"

    return "FAIL"


# ============================================================
# TSHARK PARSER
# ============================================================

def parse_diameter_packets(pcap_file):

    command = [
        "tshark",
        "-r",
        pcap_file,

        "-Y",
        "diameter",

        "-T",
        "fields",

        "-E",
        "separator=\t",

        "-E",
        "quote=d",

        # Basic packet information
        "-e",
        "frame.number",

        "-e",
        "frame.time_relative",

        "-e",
        "ip.src",

        "-e",
        "ip.dst",

        # Diameter header
        "-e",
        "diameter.cmd.code",

        "-e",
        "diameter.flags.request",

        "-e",
        "diameter.hopbyhopid",

        "-e",
        "diameter.answer_in",

        "-e",
        "diameter.answer_to",

        "-e",
        "diameter.resp_time",

        "-e",
        "diameter.Result-Code",

        "-e",
        "diameter.applicationId",

        # Session information
        "-e",
        "diameter.Session-Id",

        "-e",
        "diameter.User-Name",

        # Routing information
        "-e",
        "diameter.Origin-Host",

        "-e",
        "diameter.Origin-Realm",

        "-e",
        "diameter.Destination-Host",

        "-e",
        "diameter.Destination-Realm",

        # Accounting
        "-e",
        "diameter.Accounting-Record-Type",

        "-e",
        "diameter.Accounting-Record-Number",
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )

    except subprocess.CalledProcessError as exc:

        print(
            "TShark failed:",
            exc.stderr,
            file=sys.stderr
        )

        return []

    packets = []

    for line in result.stdout.splitlines():

        if not line.strip():
            continue

        fields = line.split("\t")

        # We expect 18 fields.
        if len(fields) < 18:
            continue

        frame_number = parse_int(fields[0])
        time_relative = parse_float(fields[1])

        source = clean(fields[2])
        destination = clean(fields[3])

        command_code = parse_int(fields[4])

        request_flag = clean(fields[5])

        is_request = request_flag == "1"

        hop_by_hop_id = clean(fields[6])

        answer_in = parse_int(fields[7])
        answer_to = parse_int(fields[8])

        response_time = parse_float(fields[9])

        result_code = parse_int(fields[10])

        application_id = parse_int(fields[11])

        session_id = clean(fields[12])
        user_name = clean(fields[13])

        origin_host = clean(fields[14])
        origin_realm = clean(fields[15])

        destination_host = clean(fields[16])
        destination_realm = clean(fields[17])

        accounting_record_type = None
        accounting_record_number = None

        if len(fields) > 18:
            accounting_record_type = parse_int(fields[18])

        if len(fields) > 19:
            accounting_record_number = parse_int(fields[19])

        packet = DiameterPacket(

            frame_number=frame_number,

            time_relative=time_relative,

            source=source,

            destination=destination,

            command_code=command_code,

            is_request=is_request,

            hop_by_hop_id=hop_by_hop_id,

            answer_in=answer_in,

            answer_to=answer_to,

            response_time=response_time,

            result_code=result_code,

            application_id=application_id,

            session_id=session_id,

            user_name=user_name,

            origin_host=origin_host,

            origin_realm=origin_realm,

            destination_host=destination_host,

            destination_realm=destination_realm,

            accounting_record_type=accounting_record_type,

            accounting_record_number=accounting_record_number,
        )

        packets.append(packet)

    return packets


# ============================================================
# TRANSACTION CORRELATION
# ============================================================

def correlate_transactions(packets):

    packet_map = {
        packet.frame_number: packet
        for packet in packets
    }

    transactions = []

    for answer in packets:

        # Ignore requests
        if answer.is_request:
            continue

        # Wireshark provides the original request frame
        # through answer_to.
        if answer.answer_to is None:
            continue

        request = packet_map.get(answer.answer_to)

        if request is None:
            continue

        # Calculate latency
        if answer.response_time is not None:

            latency_ms = (
                answer.response_time * 1000
            )

        else:

            latency_ms = (
                answer.time_relative
                - request.time_relative
            ) * 1000

        # Result
        result = result_status(
            answer.result_code
        )

        # Prefer answer information where appropriate.
        command_code = (
            answer.command_code
            if answer.command_code is not None
            else request.command_code
        )

        application_id = (
            answer.application_id
            if answer.application_id is not None
            else request.application_id
        )

        session_id = (
            answer.session_id
            or request.session_id
        )

        origin_host = (
            request.origin_host
            or answer.origin_host
        )

        accounting_record_type = (
            answer.accounting_record_type
            if answer.accounting_record_type is not None
            else request.accounting_record_type
        )

        accounting_record_number = (
            answer.accounting_record_number
            if answer.accounting_record_number is not None
            else request.accounting_record_number
        )

        transaction = DiameterTransaction(

            request_frame=request.frame_number,

            answer_frame=answer.frame_number,

            command_code=command_code,

            command_name=command_name(
                command_code
            ),

            application_id=application_id,

            application_name=application_name(
                application_id
            ),

            request_source=request.source,

            request_destination=request.destination,

            answer_source=answer.source,

            answer_destination=answer.destination,

            request_time=request.time_relative,

            answer_time=answer.time_relative,

            latency_ms=latency_ms,

            result_code=answer.result_code,

            result=result,

            session_id=session_id,

            origin_host=origin_host,

            accounting_record_type=accounting_record_type,

            accounting_record_type_name=accounting_type_name(
                accounting_record_type
            ),

            accounting_record_number=accounting_record_number,

            request_origin_host=request.origin_host,
            answer_origin_host=answer.origin_host,
        )

        transactions.append(transaction)

    return transactions


# ============================================================
# TRANSACTION CLASSIFICATION
# ============================================================

def classify_transaction(transaction):

    command_code = transaction.command_code
    application_id = transaction.application_id

    if (
        command_code == 280
        and application_id == 0
    ):
        return "DEVICE_WATCHDOG"

    if (
        command_code == 271
        and application_id == 3
    ):
        return "ACCOUNTING"

    return "OTHER"


# ============================================================
# SUMMARY
# ============================================================

def summarize_transactions(transactions):

    summary = {}

    for transaction in transactions:

        classification = classify_transaction(
            transaction
        )

        key = (
            classification,
            transaction.command_code,
            transaction.application_id,
        )

        if key not in summary:

            summary[key] = {

                "classification": classification,

                "command_code":
                    transaction.command_code,

                "command_name":
                    transaction.command_name,

                "application_id":
                    transaction.application_id,

                "application_name":
                    transaction.application_name,

                "count": 0,

                "successful": 0,

                "failed": 0,

                "unknown": 0,

                "latency_min_ms": None,

                "latency_max_ms": None,

                "latency_avg_ms": None,

                "_latencies": [],
            }

        item = summary[key]

        item["count"] += 1

        if transaction.result == "PASS":

            item["successful"] += 1

        elif transaction.result == "FAIL":

            item["failed"] += 1

        else:

            item["unknown"] += 1

        item["_latencies"].append(
            transaction.latency_ms
        )

    # Calculate latency statistics
    for item in summary.values():

        latencies = item.pop(
            "_latencies"
        )

        if latencies:

            item["latency_min_ms"] = min(
                latencies
            )

            item["latency_max_ms"] = max(
                latencies
            )

            item["latency_avg_ms"] = (
                sum(latencies)
                / len(latencies)
            )

    return list(summary.values())


# ============================================================
# ACCOUNTING SUMMARY
# ============================================================

def summarize_accounting(transactions):

    accounting = {

        "total_transactions": 0,

        "successful": 0,

        "failed": 0,

        "unknown": 0,

        "record_types": {

            "START": 0,

            "INTERIM": 0,

            "STOP": 0,

            "EVENT": 0,

            "UNKNOWN": 0,
        },

        "pcscf_nodes": {},

        "sessions": {},
    }

    for transaction in transactions:

        if classify_transaction(
            transaction
        ) != "ACCOUNTING":

            continue

        accounting[
            "total_transactions"
        ] += 1

        if transaction.result == "PASS":

            accounting["successful"] += 1

        elif transaction.result == "FAIL":

            accounting["failed"] += 1

        else:

            accounting["unknown"] += 1

        record_type = (
            transaction.accounting_record_type_name
            or "UNKNOWN"
        )

        if record_type not in accounting[
            "record_types"
        ]:

            accounting[
                "record_types"
            ][record_type] = 0

        accounting[
            "record_types"
        ][record_type] += 1

        # P-CSCF node
        origin_host = (
            transaction.origin_host
            or "UNKNOWN"
        )

        if origin_host not in accounting[
            "pcscf_nodes"
        ]:

            accounting[
                "pcscf_nodes"
            ][origin_host] = {

                "transactions": 0,

                "successful": 0,

                "failed": 0,
            }

        node = accounting[
            "pcscf_nodes"
        ][origin_host]

        node["transactions"] += 1

        if transaction.result == "PASS":

            node["successful"] += 1

        elif transaction.result == "FAIL":

            node["failed"] += 1

        # Session
        if transaction.session_id:

            session_id = (
                transaction.session_id
            )

            if session_id not in accounting[
                "sessions"
            ]:

                accounting[
                    "sessions"
                ][session_id] = {

                    "origin_host":
                        origin_host,

                    "record_types": [],

                    "record_numbers": [],
                }

            session = accounting[
                "sessions"
            ][session_id]

            if (
                transaction.accounting_record_type_name
                not in session["record_types"]
            ):

                session[
                    "record_types"
                ].append(
                    transaction.accounting_record_type_name
                )

            if (
                transaction.accounting_record_number
                is not None
            ):

                if (
                    transaction.accounting_record_number
                    not in session[
                        "record_numbers"
                    ]
                ):

                    session[
                        "record_numbers"
                    ].append(
                        transaction.accounting_record_number
                    )

    return accounting


# ============================================================
# DIAMETER HEALTH
# ============================================================

def analyze_diameter_health(
    packets,
    transactions,
):

    watchdog = [
        tx
        for tx in transactions
        if classify_transaction(tx)
        == "DEVICE_WATCHDOG"
    ]

    accounting = [
        tx
        for tx in transactions
        if classify_transaction(tx)
        == "ACCOUNTING"
    ]

    other = [
        tx
        for tx in transactions
        if classify_transaction(tx)
        == "OTHER"
    ]

    # Cx isn't present in the current capture.
    ims_cx_observed = any(
        tx.application_id == 16777216
        for tx in transactions
    )

    return {

        "total_packets":
            len(packets),

        "total_transactions":
            len(transactions),

        "device_watchdog": {

            "transactions":
                len(watchdog),

            "successful":
                sum(
                    1
                    for tx in watchdog
                    if tx.result == "PASS"
                ),

            "failed":
                sum(
                    1
                    for tx in watchdog
                    if tx.result == "FAIL"
                ),
        },

        "accounting": {

            "transactions":
                len(accounting),

            "successful":
                sum(
                    1
                    for tx in accounting
                    if tx.result == "PASS"
                ),

            "failed":
                sum(
                    1
                    for tx in accounting
                    if tx.result == "FAIL"
                ),
        },

        "other": {

            "transactions":
                len(other),
        },

        "ims_cx": {

            "observed":
                ims_cx_observed,

            "status":
                (
                    "OBSERVED"
                    if ims_cx_observed
                    else "NOT OBSERVED"
                ),
        },
    }


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_diameter(pcap_file):

    packets = parse_diameter_packets(
        pcap_file
    )

    transactions = correlate_transactions(
        packets
    )

    summary = summarize_transactions(
        transactions
    )

    accounting_summary = (
        summarize_accounting(
            transactions
        )
    )

    health = analyze_diameter_health(
        packets,
        transactions,
    )

    return {

        "packet_count":
            len(packets),

        "transaction_count":
            len(transactions),

        "successful":
            sum(
                1
                for tx in transactions
                if tx.result == "PASS"
            ),

        "failed":
            sum(
                1
                for tx in transactions
                if tx.result == "FAIL"
            ),

        "unknown":
            sum(
                1
                for tx in transactions
                if tx.result == "UNKNOWN"
            ),

        "summary":
            summary,

        "accounting":
            accounting_summary,

        "health":
            health,

        "transactions":
            transactions,
    }


# ============================================================
# TERMINAL REPORT
# ============================================================

def print_report(result):

    print()
    print("=" * 70)
    print("DIAMETER ANALYZER")
    print("=" * 70)

    print(
        f"Diameter packets      : "
        f"{result['packet_count']}"
    )

    print(
        f"Transactions          : "
        f"{result['transaction_count']}"
    )

    print(
        f"Successful            : "
        f"{result['successful']}"
    )

    print(
        f"Failed                : "
        f"{result['failed']}"
    )

    print(
        f"Unknown               : "
        f"{result['unknown']}"
    )

    print()

    print("-" * 70)
    print("DIAMETER MESSAGE SUMMARY")
    print("-" * 70)

    for item in result["summary"]:

        print(
            f"{item['command_name']:<22} "
            f"CMD {item['command_code']:<5} "
            f"APP {item['application_id']:<5} "
            f"Count {item['count']:<5} "
            f"PASS {item['successful']:<5} "
            f"FAIL {item['failed']:<5}"
        )

    print()

    print("-" * 70)
    print("ACCOUNTING SUMMARY")
    print("-" * 70)

    accounting = result[
        "accounting"
    ]

    print(
        f"Transactions : "
        f"{accounting['total_transactions']}"
    )

    print(
        f"Successful   : "
        f"{accounting['successful']}"
    )

    print(
        f"Failed       : "
        f"{accounting['failed']}"
    )

    print()

    print("Accounting Record Types:")

    for (
        record_type,
        count
    ) in accounting[
        "record_types"
    ].items():

        print(
            f"  {record_type:<10} : {count}"
        )

    print()

    print("P-CSCF Nodes:")

    for (
        node,
        values
    ) in accounting[
        "pcscf_nodes"
    ].items():

        print(
            f"  {node}"
        )

        print(
            f"      Transactions : "
            f"{values['transactions']}"
        )

        print(
            f"      Successful   : "
            f"{values['successful']}"
        )

        print(
            f"      Failed       : "
            f"{values['failed']}"
        )

    print()

    print("-" * 70)
    print("DIAMETER HEALTH")
    print("-" * 70)

    health = result["health"]

    watchdog = health[
        "device_watchdog"
    ]

    print(
        f"Device-Watchdog "
        f": {watchdog['transactions']} "
        f"transactions | "
        f"{watchdog['successful']} successful | "
        f"{watchdog['failed']} failed"
    )

    cx = health["ims_cx"]

    print(
        f"IMS Cx             : "
        f"{cx['status']}"
    )

    print()

    print("-" * 70)
    print("FIRST 10 TRANSACTIONS")
    print("-" * 70)

    for tx in result[
        "transactions"
    ][:10]:

        record = ""

        if tx.accounting_record_type_name:

            record = (
                f" | "
                f"{tx.accounting_record_type_name}"
            )

        print(
            f"{tx.request_frame} -> "
            f"{tx.answer_frame} | "
            f"CMD {tx.command_code} "
            f"({tx.command_name}) | "
            f"{tx.result} | "
            f"{tx.latency_ms:.3f} ms | "
            f"Result {tx.result_code}"
            f"{record}"
        )

    print("=" * 70)


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python3 "
            "backend/app/analyzer/"
            "diameter_analyzer.py "
            "captures/registration.pcapng"
        )

        sys.exit(1)

    pcap_file = sys.argv[1]

    result = analyze_diameter(
        pcap_file
    )

    print_report(result)
