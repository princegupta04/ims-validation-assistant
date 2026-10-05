import os
import shutil
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from backend.app.analyzer.pcap_analyzer import analyze_pcap
from backend.app.analyzer.registration_analyzer import analyze_registration
from backend.app.analyzer.root_cause_engine import analyze_registration_root_cause
from backend.app.analyzer.registration_flow_validator import validate_registration_flow
from backend.app.analyzer.call_analyzer import analyze_calls
from backend.app.analyzer.diameter_analyzer import analyze_diameter
from backend.app.analyzer.report_generator import generate_validation_report
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(
    title="IMS Validation Assistant",
    version="0.2.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://ims-validation-assistant-frontend.onrender.com/",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "application": "IMS Validation Assistant",
        "version": "0.2.0",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/analyze")
async def analyze_capture(file: UploadFile = File(...)):
    """
    Upload a PCAP/PCAPNG file and run the complete
    IMS validation pipeline.
    """

    filename = file.filename or ""

    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are supported.",
        )

    temp_path = None

    try:
        # -----------------------------------------------------
        # Save uploaded PCAP to temporary location
        # -----------------------------------------------------

        suffix = os.path.splitext(filename)[1]

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
        ) as temp_file:

            temp_path = temp_file.name

            shutil.copyfileobj(
                file.file,
                temp_file,
            )

        # -----------------------------------------------------
        # 1. SIP Packet Parsing
        # -----------------------------------------------------

        sip_packets = analyze_pcap(temp_path)

        # -----------------------------------------------------
        # 2. IMS Registration Validation
        # -----------------------------------------------------

        registration = analyze_registration(
            sip_packets
        )

        # -----------------------------------------------------
        # 3. Root Cause Analysis
        # -----------------------------------------------------

        root_cause = analyze_registration_root_cause(
            registration
        )

        # -----------------------------------------------------
        # 4. IMS Signaling Flow Validation
        # -----------------------------------------------------

        registration_flow = validate_registration_flow(
            sip_packets,
            registration,
        )

        # -----------------------------------------------------
        # 5. IMS Call Validation
        # -----------------------------------------------------

        call_validation = analyze_calls(
            sip_packets
        )

        # -----------------------------------------------------
        # 6. Diameter Analysis
        # -----------------------------------------------------

        diameter = analyze_diameter(
            temp_path
        )

        # -----------------------------------------------------
        # Engineer-Friendly Validation Report
        # -----------------------------------------------------

        validation_report = generate_validation_report(
            registration,
            root_cause,
            registration_flow,
            call_validation,
            diameter,
        )

        # -----------------------------------------------------
        # Final API response
        # -----------------------------------------------------

        return {
            "filename": filename,

            "validation_report": validation_report,

            "details": {
                "registration": registration,
                "root_cause": root_cause,
                "registration_flow": registration_flow,
                "call_validation": call_validation,
                "diameter": diameter,
            },
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {str(exc)}",
        )

    finally:
        # -----------------------------------------------------
        # Remove temporary PCAP
        # -----------------------------------------------------

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

        await file.close()
