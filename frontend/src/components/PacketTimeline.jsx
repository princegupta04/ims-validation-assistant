import { useMemo, useState } from "react";
import RegisterComparison from "./RegisterComparison.jsx";

function getStatusCode(packet) {
  const value = packet?.status_code ?? packet?.statusCode;

  if (value === null || value === undefined || value === "") {
    return null;
  }

  const parsed = Number(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function getMethod(packet) {
  return packet?.method || packet?.sip_method || "";
}

function getFrame(packet) {
  return packet?.frame ?? packet?.frame_number ?? packet?.frameNumber ?? "";
}

function getTime(packet) {
  return (
    packet?.time_relative ??
    packet?.time ??
    packet?.timestamp ??
    ""
  );
}

function getCallId(packet) {
  return packet?.call_id || packet?.callId || "";
}

function getCseq(packet) {
  return packet?.cseq || packet?.c_seq || "";
}

function getSource(packet) {
  return packet?.source || packet?.src || packet?.ip_src || "";
}

function getDestination(packet) {
  return packet?.destination || packet?.dst || packet?.ip_dst || "";
}

function getRequestLine(packet) {
  return packet?.request_line || packet?.requestLine || "";
}

function getStatusLine(packet) {
  return packet?.status_line || packet?.statusLine || "";
}

function getHeaders(packet) {
  return packet?.sip_headers || packet?.sipHeaders || "";
}

function getBody(packet) {
  return packet?.sip_body || packet?.sipBody || "";
}

function isRegister(packet) {
  return getMethod(packet).toUpperCase() === "REGISTER";
}

function isFailure(packet) {
  const status = getStatusCode(packet);
  return status !== null && status >= 400;
}

function getPacketLabel(packet) {
  const method = getMethod(packet);
  const status = getStatusCode(packet);

  if (method) {
    return method;
  }

  if (status) {
    return `SIP ${status}`;
  }

  return "SIP";
}

function getPacketClass(packet, selected) {
  const classes = ["timeline-packet"];

  if (selected) {
    classes.push("selected");
  }

  if (isRegister(packet)) {
    classes.push("register");
  }

  if (isFailure(packet)) {
    classes.push("failure");
  }

  const status = getStatusCode(packet);

  if (status >= 100 && status < 200) {
    classes.push("provisional");
  }

  if (status >= 200 && status < 300) {
    classes.push("success");
  }

  return classes.join(" ");
}

function PacketDetails({ packet, timeline }) {
  if (!packet) {
    return (
      <div className="packet-details empty-state">
        <div className="empty-icon">📦</div>
        <h3>Select a packet</h3>
        <p>
          Select a packet from the timeline to inspect its SIP details.
        </p>
      </div>
    );
  }

  const status = getStatusCode(packet);
  const method = getMethod(packet);
  const headers = getHeaders(packet);
  const body = getBody(packet);

  const copyToClipboard = async (value) => {
    if (!value) {
      return;
    }

    try {
      await navigator.clipboard.writeText(value);
    } catch (error) {
      console.error("Unable to copy:", error);
    }
  };

  return (
    <div className="packet-details">
      <div className="packet-details-header">
        <div>
          <span className="packet-details-label">Packet</span>
          <h2>
            Frame {getFrame(packet)} — {getPacketLabel(packet)}
          </h2>
        </div>

        {status !== null && (
          <span
            className={`status-badge ${
              status >= 400
                ? "status-fail"
                : status >= 200
                ? "status-success"
                : "status-info"
            }`}
          >
            {status}
          </span>
        )}
      </div>

      <div className="packet-info-grid">
        <div className="packet-info-item">
          <span>Frame</span>
          <strong>{getFrame(packet) || "—"}</strong>
        </div>

        <div className="packet-info-item">
          <span>Time</span>
          <strong>{getTime(packet) || "—"}</strong>
        </div>

        <div className="packet-info-item">
          <span>Method</span>
          <strong>{method || "—"}</strong>
        </div>

        <div className="packet-info-item">
          <span>Status</span>
          <strong>
            {status !== null ? status : "—"}
          </strong>
        </div>

        <div className="packet-info-item">
          <span>Source</span>
          <strong>{getSource(packet) || "—"}</strong>
        </div>

        <div className="packet-info-item">
          <span>Destination</span>
          <strong>{getDestination(packet) || "—"}</strong>
        </div>

        <div className="packet-info-item">
          <span>Call-ID</span>
          <strong>{getCallId(packet) || "—"}</strong>
        </div>

        <div className="packet-info-item">
          <span>CSeq</span>
          <strong>{getCseq(packet) || "—"}</strong>
        </div>
      </div>

      {getRequestLine(packet) && (
        <div className="packet-field">
          <span>Request-Line</span>
          <code>{getRequestLine(packet)}</code>
        </div>
      )}

      {getStatusLine(packet) && (
        <div className="packet-field">
          <span>Status-Line</span>
          <code>{getStatusLine(packet)}</code>
        </div>
      )}

      {isFailure(packet) && (
        <div className="packet-alert">
          <div className="packet-alert-icon">⚠</div>
          <div>
            <strong>SIP Failure Response</strong>
            <p>
              This packet contains a SIP response in the failure range
              ({status}). Inspect the SIP headers and compare it with the
              preceding REGISTER transaction.
            </p>
          </div>
        </div>
      )}

      {/* Automatic REGISTER comparison */}
      <RegisterComparison
        selectedPacket={packet}
        timeline={timeline}
      />

      <div className="sip-section">
        <div className="sip-section-header">
          <div>
            <span className="packet-details-label">SIP Message</span>
            <h3>Headers</h3>
          </div>

          {headers && (
            <button
              className="copy-button"
              onClick={() => copyToClipboard(headers)}
              type="button"
            >
              Copy
            </button>
          )}
        </div>

        {headers ? (
          <pre className="sip-raw-content">{headers}</pre>
        ) : (
          <div className="sip-empty">
            No SIP headers available for this packet.
          </div>
        )}
      </div>

      <div className="sip-section">
        <div className="sip-section-header">
          <div>
            <span className="packet-details-label">SIP Message</span>
            <h3>Body</h3>
          </div>

          {body && (
            <button
              className="copy-button"
              onClick={() => copyToClipboard(body)}
              type="button"
            >
              Copy
            </button>
          )}
        </div>

        {body ? (
          <pre className="sip-raw-content">{body}</pre>
        ) : (
          <div className="sip-empty">
            No SIP body available for this packet.
          </div>
        )}
      </div>
    </div>
  );
}

export default function PacketTimeline({ registration }) {
  const [search, setSearch] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);

  const sessions = registration?.sessions || [];

  const timeline = useMemo(() => {
    if (!sessions.length) {
      return [];
    }

    // Prefer the first session that actually has a timeline.
    const sessionWithTimeline =
      sessions.find(
        (session) =>
          Array.isArray(session?.timeline) &&
          session.timeline.length > 0
      ) || sessions[0];

    return Array.isArray(sessionWithTimeline?.timeline)
      ? sessionWithTimeline.timeline
      : [];
  }, [sessions]);

  const importantPackets = useMemo(() => {
    return timeline.filter((packet) => {
      return isRegister(packet) || isFailure(packet);
    });
  }, [timeline]);

  const packetsToDisplay = showAll ? timeline : importantPackets;

  const visiblePackets = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) {
      return packetsToDisplay;
    }

    return packetsToDisplay.filter((packet) => {
      const searchableText = [
        getFrame(packet),
        getTime(packet),
        getMethod(packet),
        getStatusCode(packet),
        getCallId(packet),
        getCseq(packet),
        getSource(packet),
        getDestination(packet),
        getRequestLine(packet),
        getStatusLine(packet),
        getHeaders(packet),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return searchableText.includes(query);
    });
  }, [packetsToDisplay, search]);

  const selectedFrame = getFrame(selectedPacket);

  const selectPacket = (packet) => {
    setSelectedPacket(packet);
  };

  return (
    <div className="investigation-page">
      <div className="investigation-header">
        <div>
          <button
            className="back-button"
            type="button"
            onClick={() => window.history.back()}
          >
            ← Back
          </button>

          <div className="investigation-title">
            <span className="section-eyebrow">
              Packet-Level Investigation
            </span>

            <h1>Registration Signaling Timeline</h1>

            <p>
              Inspect SIP packets, registration failures, and automatic
              REGISTER header differences.
            </p>
          </div>
        </div>

        <div className="investigation-stats">
          <div className="investigation-stat">
            <span>Total Packets</span>
            <strong>{timeline.length}</strong>
          </div>

          <div className="investigation-stat">
            <span>Important</span>
            <strong>{importantPackets.length}</strong>
          </div>

          <div className="investigation-stat">
            <span>Showing</span>
            <strong>{visiblePackets.length}</strong>
          </div>
        </div>
      </div>

      <div className="investigation-toolbar">
        <div className="search-box">
          <span className="search-icon">⌕</span>

          <input
            type="text"
            placeholder="Search frame, method, Call-ID, CSeq, IP..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

          {search && (
            <button
              type="button"
              className="search-clear"
              onClick={() => setSearch("")}
            >
              ×
            </button>
          )}
        </div>

        <div className="timeline-toggle">
          <button
            type="button"
            className={!showAll ? "active" : ""}
            onClick={() => setShowAll(false)}
          >
            Important
          </button>

          <button
            type="button"
            className={showAll ? "active" : ""}
            onClick={() => setShowAll(true)}
          >
            All Packets
          </button>
        </div>
      </div>

      {!timeline.length ? (
        <div className="empty-state investigation-empty">
          <div className="empty-icon">📭</div>
          <h2>No packet timeline available</h2>
          <p>
            The analyzer did not return packet-level registration data for
            this capture.
          </p>
        </div>
      ) : (
        <div className="investigation-layout">
          <div className="timeline-panel">
            <div className="timeline-panel-header">
              <div>
                <span className="section-eyebrow">SIP Flow</span>
                <h2>Packet Timeline</h2>
              </div>

              <span className="timeline-count">
                {visiblePackets.length} packet
                {visiblePackets.length === 1 ? "" : "s"}
              </span>
            </div>

            <div className="timeline-list">
              {visiblePackets.length === 0 ? (
                <div className="timeline-no-results">
                  <strong>No matching packets</strong>
                  <span>
                    Try another frame number, SIP method, status code,
                    Call-ID, or IP address.
                  </span>
                </div>
              ) : (
                visiblePackets.map((packet, index) => {
                  const frame = getFrame(packet);
                  const status = getStatusCode(packet);
                  const method = getMethod(packet);
                  const selected = selectedFrame === frame;

                  return (
                    <button
                      key={`${frame}-${index}`}
                      type="button"
                      className={getPacketClass(packet, selected)}
                      onClick={() => selectPacket(packet)}
                    >
                      <div className="timeline-packet-marker">
                        <span />
                      </div>

                      <div className="timeline-packet-content">
                        <div className="timeline-packet-top">
                          <span className="timeline-frame">
                            Frame {frame || "—"}
                          </span>

                          <span className="timeline-time">
                            {getTime(packet) || "—"}
                          </span>
                        </div>

                        <div className="timeline-packet-main">
                          <strong>
                            {getPacketLabel(packet)}
                          </strong>

                          {status !== null && (
                            <span
                              className={`timeline-status ${
                                status >= 400
                                  ? "failure"
                                  : status >= 200
                                  ? "success"
                                  : "info"
                              }`}
                            >
                              {status}
                            </span>
                          )}
                        </div>

                        <div className="timeline-packet-meta">
                          {getCseq(packet) && (
                            <span>CSeq {getCseq(packet)}</span>
                          )}

                          {getCallId(packet) && (
                            <span>
                              Call-ID: {getCallId(packet)}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="timeline-arrow">›</div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          <PacketDetails
            packet={selectedPacket}
            timeline={timeline}
          />
        </div>
      )}
    </div>
  );
}
