import { useState } from "react";
import "./App.css";
import PacketTimeline from "./components/PacketTimeline.jsx";

const API_URL =  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function App() {
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [showInvestigation, setShowInvestigation] = useState(false);

  const handleFile = (selectedFile) => {
    setError("");
    setResult(null);

    if (!selectedFile) return;

    const valid = [".pcap", ".pcapng"].some((ext) =>
      selectedFile.name.toLowerCase().endsWith(ext)
    );

    if (!valid) {
      setFile(null);
      setError("Please select a .pcap or .pcapng file.");
      return;
    }

    setFile(selectedFile);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragging(false);

    const droppedFile = event.dataTransfer.files?.[0];
    handleFile(droppedFile);
  };

  const analyzeFile = async () => {
    if (!file) {
      setError("Please select a PCAP file first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Analysis failed.");
      }

      setResult(data);
    } catch (err) {
      setError(err.message || "Unable to connect to the backend.");
    } finally {
      setLoading(false);
    }
  };

  const report = result?.validation_report;
  const details = result?.details;

  const registration = details?.registration;
  const registrationFlow = details?.registration_flow;
  const calls = details?.call_validation;
  const diameter = details?.diameter;
  const rootCauseReport = details?.root_cause;

  const rootCauseSession =
    rootCauseReport?.sessions?.find((session) => session.root_cause) ||
    null;

  const rootCause = rootCauseSession?.root_cause || null;

  if (showInvestigation && result) {
    return (
      <div className="app">
        <header className="header">
          <div>
            <div className="brand">IMS VALIDATION ASSISTANT</div>
            <div className="subtitle">
              Packet-level IMS investigation
            </div>
          </div>

          <button
            className="back-button"
            onClick={() => setShowInvestigation(false)}
          >
            ← Back to Dashboard
          </button>
        </header>

        <main className="container">
          <PacketTimeline registration={registration} />

          <button
            className="new-analysis-button"
            onClick={() => {
              setShowInvestigation(false);
              setResult(null);
              setFile(null);
              setError("");
            }}
          >
            Analyze another PCAP
          </button>
        </main>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <div>
          <div className="brand">IMS VALIDATION ASSISTANT</div>
          <div className="subtitle">
            PCAP-based IMS signaling & network validation
          </div>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          Analyzer Ready
        </div>
      </header>

      <main className="container">
        {!result && (
          <>
            <section className="hero">
              <h1>Validate your IMS capture</h1>
              <p>
                Upload a SIP / IMS PCAP file and automatically analyze
                registration, signaling, calls, Diameter transactions and
                root causes.
              </p>
            </section>

            <section className="upload-card">
              <div
                className={`drop-zone ${dragging ? "dragging" : ""} ${
                  file ? "has-file" : ""
                }`}
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={handleDrop}
              >
                <div className="upload-icon">⇧</div>

                {file ? (
                  <>
                    <h2>{file.name}</h2>
                    <p>{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                  </>
                ) : (
                  <>
                    <h2>Drop your PCAP here</h2>
                    <p>or choose a capture file from your computer</p>
                  </>
                )}

                <label className="choose-button">
                  Choose PCAP
                  <input
                    type="file"
                    accept=".pcap,.pcapng"
                    hidden
                    onChange={(event) =>
                      handleFile(event.target.files?.[0])
                    }
                  />
                </label>

                <span className="supported">
                  Supported formats: .pcap, .pcapng
                </span>
              </div>

              {error && <div className="error">{error}</div>}

              <button
                className="analyze-button"
                disabled={!file || loading}
                onClick={analyzeFile}
              >
                {loading ? "Analyzing PCAP..." : "Analyze Capture"}
              </button>
            </section>
          </>
        )}

        {loading && (
          <section className="loading-card">
            <div className="spinner"></div>
            <div>
              <strong>Analyzing IMS capture</strong>
              <p>
                Parsing SIP, validating registration, calls and Diameter
                transactions...
              </p>
            </div>
          </section>
        )}

        {result && report && (
          <section className="results">

            {/* HEADER */}
            <div className="results-header">
              <div>
                <span className="section-label">VALIDATION RESULT</span>
                <h2>{result.filename}</h2>
              </div>

              <div
                className={`overall ${
                  report.result === "PASS" ? "pass" : "fail"
                }`}
              >
                <span className="result-dot"></span>
                {report.result}
              </div>
            </div>

            {/* TOP SUMMARY */}
            <div className="summary-grid">

              <ResultCard
                title="IMS Registration"
                value={registration?.result}
                description={registration?.reason}
              />

              <ResultCard
                title="SIP Calls"
                value={calls?.result}
                description={calls?.reason}
              />

              <ResultCard
                title="Diameter"
                value={diameter?.health?.ims_cx?.status || diameter?.result}
                description={
                  diameter
                    ? `${diameter.transaction_count} transactions · ${diameter.successful} successful · ${diameter.failed} failed`
                    : "No Diameter data"
                }
              />

              <ResultCard
                title="Root Cause"
                value={rootCause ? "FAIL" : "NOT DETECTED"}
                description={
                  rootCause
                    ? `SIP ${rootCause.status_code} · ${rootCause.category}`
                    : "No root cause identified"
                }
              />

            </div>

            {/* ROOT CAUSE */}
            {rootCause && (
              <section className="root-cause-card">

                <div className="card-heading">
                  <span className="warning-icon">!</span>

                  <div>
                    <span className="section-label">
                      ROOT CAUSE ANALYSIS
                    </span>
                    <h3>{rootCause.category}</h3>
                  </div>
                </div>

                <div className="root-cause-content">

                  <InfoBox
                    label="Status Code"
                    value={`SIP ${rootCause.status_code}`}
                  />

                  <InfoBox
                    label="Likely Area"
                    value={rootCause.likely_area}
                  />

                  <InfoBox
                    label="Frame"
                    value={rootCause.frame}
                  />

                  <InfoBox
                    label="CSeq"
                    value={rootCause.cseq}
                  />

                  <InfoBox
                    label="Source"
                    value={rootCause.source}
                  />

                  <InfoBox
                    label="Destination"
                    value={rootCause.destination}
                  />

                  <InfoBox
                    label="Time"
                    value={`${rootCause.time}s`}
                  />

                  <InfoBox
                    label="Severity"
                    value={rootCause.severity}
                  />

                </div>

                <div className="evidence-box">
                  <span>Evidence</span>
                  <p>{rootCause.evidence}</p>
                </div>

                <div className="recommendation-box">
                  <span>Recommended Action</span>
                  <p>{rootCause.recommended_action}</p>
                </div>

              </section>
            )}

            {/* REGISTRATION FLOW */}
            <section className="flow-card">

              <div className="card-title">
                <span className="section-label">
                  IMS SIGNALING FLOW
                </span>

                <h3>Registration Path</h3>
              </div>

              <div className="flow">

                <FlowNode label="UE" active />

                <FlowArrow />

                <FlowNode
                  label="P-CSCF"
                  active={hasNode(registrationFlow, "P-CSCF")}
                />

                <FlowArrow />

                <FlowNode
                  label="I-CSCF"
                  active={hasNode(registrationFlow, "I-CSCF")}
                />

                <FlowArrow />

                <FlowNode
                  label="S-CSCF"
                  active={hasNode(registrationFlow, "S-CSCF")}
                />

                <FlowArrow />

                <FlowNode
                  label="200 OK"
                  active={registration?.result === "PASS"}
                />

              </div>

              <div className="flow-status">
                {registrationFlow?.reason}
              </div>

            </section>

            {/* REGISTRATION DETAILS */}
            <section className="details-grid">

              <DetailCard
                title="Registration"
                items={[
                  ["Result", registration?.result],
                  ["REGISTER Packets", registration?.register_count],
                  ["Sessions", registration?.session_count],
                  ["Successful", registration?.successful_sessions],
                  ["Failed", registration?.failed_sessions],
                  ["Incomplete", registration?.incomplete_sessions],
                ]}
              />

              <DetailCard
                title="SIP Calls"
                items={[
                  ["Result", calls?.result],
                  ["Total Calls", calls?.call_count],
                  ["Successful", calls?.successful_calls],
                  ["Failed", calls?.failed_calls],
                  ["Incomplete", calls?.incomplete_calls],
                ]}
              />

              <DetailCard
                title="Diameter"
                items={[
                  ["Result", diameter?.successful === diameter?.transaction_count ? "PASS" : "CHECK"],
                  ["Packets", diameter?.packet_count],
                  ["Transactions", diameter?.transaction_count],
                  ["Successful", diameter?.successful],
                  ["Failed", diameter?.failed],
                  ["Unknown", diameter?.unknown],
                  [
                    "Cx",
                    diameter?.health?.ims_cx?.status || "NOT OBSERVED",
                  ],
                ]}
              />

            </section>

            {/* DIAMETER DETAILS */}
            {diameter?.summary?.length > 0 && (
              <section className="table-card">

                <div className="card-title">
                  <span className="section-label">
                    DIAMETER ANALYSIS
                  </span>
                  <h3>Transaction Summary</h3>
                </div>

                <div className="table-wrapper">

                  <table>
                    <thead>
                      <tr>
                        <th>Command</th>
                        <th>Application</th>
                        <th>Count</th>
                        <th>Successful</th>
                        <th>Failed</th>
                        <th>Avg Latency</th>
                      </tr>
                    </thead>

                    <tbody>
                      {diameter.summary.map((item, index) => (
                        <tr key={index}>
                          <td>{item.command_name}</td>
                          <td>{item.application_name}</td>
                          <td>{item.count}</td>
                          <td className="success-text">
                            {item.successful}
                          </td>
                          <td className="failure-text">
                            {item.failed}
                          </td>
                          <td>
                            {item.latency_avg_ms?.toFixed(3)} ms
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                </div>

              </section>
            )}

            {/* REGISTRATION SESSION */}
            {registration?.sessions?.length > 0 && (
              <section className="table-card">

                <div className="card-title">
                  <span className="section-label">
                    REGISTRATION SESSIONS
                  </span>

                  <h3>Subscriber Analysis</h3>
                </div>

                <div className="table-wrapper">

                  <table>
                    <thead>
                      <tr>
                        <th>Subscriber</th>
                        <th>Result</th>
                        <th>Initial CSeq</th>
                        <th>Authenticated CSeq</th>
                        <th>Challenge</th>
                        <th>Failure</th>
                      </tr>
                    </thead>

                    <tbody>
                      {registration.sessions.map((session, index) => (
                        <tr key={index}>
                          <td>{session.subscriber}</td>

                          <td>
                            <span
                              className={
                                session.result === "PASS"
                                  ? "badge-pass"
                                  : "badge-fail"
                              }
                            >
                              {session.result}
                            </span>
                          </td>

                          <td>{session.initial_cseq ?? "—"}</td>

                          <td>
                            {session.authenticated_cseq ?? "—"}
                          </td>

                          <td>
                            {session.authentication_challenge
                              ? "Yes"
                              : "No"}
                          </td>

                          <td>
                            {session.failure
                              ? `SIP ${session.failure.status_code} · Frame ${session.failure.frame_number}`
                              : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                </div>

              </section>
            )}

            <button
              className="investigation-button"
              onClick={() => setShowInvestigation(true)}
            >
              View Packet-Level Investigation
              <span>→</span>
            </button>

            {/* BACK BUTTON */}
            <button
              className="new-analysis-button"
              onClick={() => {
                setResult(null);
                setFile(null);
                setError("");
              }}
            >
              ← Analyze another PCAP
            </button>

          </section>
        )}
      </main>
    </div>
  );
}

function hasNode(flow, node) {
  return flow?.observed_nodes?.includes(node) || false;
}

function InfoBox({ label, value }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value ?? "Not available"}</strong>
    </div>
  );
}

function ResultCard({ title, value, description }) {
  const normalized = value || "NOT OBSERVED";

  let className = "neutral";

  if (normalized === "PASS") className = "pass";
  if (normalized === "FAIL") className = "fail";

  return (
    <div className="result-card">

      <div className="result-card-top">
        <span>{title}</span>

        <strong className={className}>
          {normalized}
        </strong>
      </div>

      <p>
        {description || "No information observed in this capture."}
      </p>

    </div>
  );
}

function FlowNode({ label, active }) {
  return (
    <div className={`flow-node ${active ? "active" : ""}`}>

      <div className="flow-circle"></div>

      <span>{label}</span>

    </div>
  );
}

function FlowArrow() {
  return <div className="flow-arrow">→</div>;
}

function DetailCard({ title, items }) {
  return (
    <div className="detail-card">

      <h3>{title}</h3>

      {items.map(([label, value]) => (
        <div className="detail-row" key={label}>

          <span>{label}</span>

          <strong>
            {value !== undefined && value !== null
              ? value
              : "—"}
          </strong>

        </div>
      ))}

    </div>
  );
}

export default App;
