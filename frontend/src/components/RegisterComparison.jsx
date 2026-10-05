import { useMemo } from "react";


function RegisterComparison({
  selectedPacket,
  timeline,
}) {

  const comparison = useMemo(() => {
    return buildRegisterComparison(
      selectedPacket,
      timeline
    );
  }, [selectedPacket, timeline]);


  if (!comparison) {
    return null;
  }


  const {
    previous,
    current,
    differences,
  } = comparison;


  return (
    <section className="register-comparison">

      <div className="comparison-header">

        <div>

          <span className="section-label">
            AUTOMATIC ANALYSIS
          </span>

          <h3>
            REGISTER Header Comparison
          </h3>

          <p className="comparison-description">
            Automatically compares the selected REGISTER
            with the previous REGISTER from the same
            registration session.
          </p>

        </div>

        <span className="comparison-count">
          {differences.length}{" "}
          {differences.length === 1
            ? "change"
            : "changes"}
        </span>

      </div>


      {/* REGISTER SEQUENCE */}

      <div className="comparison-sequence">

        <div className="comparison-packet">

          <span>
            Previous REGISTER
          </span>

          <strong>
            Frame {previous.frame}
          </strong>

          <small>
            CSeq {previous.cseq}{" "}
            {previous.cseq_method || ""}
          </small>

        </div>


        <span className="comparison-arrow">
          →
        </span>


        <div className="comparison-packet current">

          <span>
            Current REGISTER
          </span>

          <strong>
            Frame {current.frame}
          </strong>

          <small>
            CSeq {current.cseq}{" "}
            {current.cseq_method || ""}
          </small>

        </div>

      </div>


      {/* DIFFERENCES */}

      {differences.length === 0 ? (

        <div className="comparison-no-change">

          No SIP header differences detected between
          these REGISTER messages.

        </div>

      ) : (

        <div className="comparison-table">

          <div className="comparison-row comparison-row-head">

            <span>
              Header
            </span>

            <span>
              Previous
            </span>

            <span>
              Current
            </span>

          </div>


          {differences.map((difference) => (

            <div
              className="comparison-row"
              key={difference.name}
            >

              <div className="comparison-header-name">

                <strong>
                  {difference.name}
                </strong>

                <span
                  className={`change-badge ${
                    difference.changeType.toLowerCase()
                  }`}
                >
                  {difference.changeType}
                </span>

              </div>


              <code>
                {difference.previous}
              </code>


              <code>
                {difference.current}
              </code>

            </div>

          ))}

        </div>

      )}


      {/* NOTE */}

      <div className="comparison-note">

        <strong>Investigation note:</strong>{" "}
        A detected header difference indicates that the
        value changed between REGISTER attempts. It does
        not by itself prove that the changed header caused
        the SIP failure.

      </div>

    </section>
  );
}


/* =========================================================
   AUTOMATIC REGISTER COMPARISON
   ========================================================= */

function buildRegisterComparison(
  selectedPacket,
  timeline
) {

  if (!selectedPacket || !timeline?.length) {
    return null;
  }


  const selectedStatus = Number(
    selectedPacket.status_code
  );


  const isFailure =
    selectedStatus >= 400;


  const isRegister =
    selectedPacket.method === "REGISTER" ||
    selectedPacket.cseq_method === "REGISTER";


  /*
   * Only show comparison when:
   *
   * 1. User selected a REGISTER
   * OR
   * 2. User selected a SIP failure response
   */

  if (!isFailure && !isRegister) {
    return null;
  }


  const callId =
    selectedPacket.call_id;


  if (!callId) {
    return null;
  }


  /*
   * Find all REGISTER requests belonging
   * to the same Call-ID.
   */

  const registers = timeline
    .filter((packet) => {

      const packetIsRegister =
        packet.method === "REGISTER" ||
        packet.cseq_method === "REGISTER";


      return (
        packetIsRegister &&
        packet.call_id === callId &&
        packet.sip_headers
      );

    })
    .sort(
      (a, b) =>
        Number(a.time || 0) -
        Number(b.time || 0)
    );


  /*
   * Need at least two REGISTER messages
   * to perform a comparison.
   */

  if (registers.length < 2) {
    return null;
  }


  let currentRegister;


  /*
   * If a REGISTER itself is selected,
   * compare that REGISTER.
   */

  if (isRegister) {

    currentRegister =
      selectedPacket;

  } else {

    /*
     * If a failure response is selected,
     * find the latest REGISTER before
     * that failure.
     */

    currentRegister =
      [...registers]
        .reverse()
        .find(
          (register) =>
            Number(register.time || 0) <=
            Number(selectedPacket.time || 0)
        );

  }


  if (!currentRegister) {
    return null;
  }


  const currentIndex =
    registers.findIndex(
      (register) =>
        register.frame ===
        currentRegister.frame
    );


  /*
   * There must be a REGISTER before
   * the current REGISTER.
   */

  if (currentIndex <= 0) {
    return null;
  }


  const previousRegister =
    registers[currentIndex - 1];


  const previousHeaders =
    parseSipHeaders(
      previousRegister.sip_headers
    );


  const currentHeaders =
    parseSipHeaders(
      currentRegister.sip_headers
    );


  const differences =
    compareHeaders(
      previousHeaders,
      currentHeaders
    );


  return {
    previous: previousRegister,
    current: currentRegister,
    differences,
  };
}


/* =========================================================
   SIP HEADER PARSER
   ========================================================= */

function parseSipHeaders(rawHeaders) {

  if (!rawHeaders) {
    return {};
  }


  const normalized =
    String(rawHeaders)
      .replace(/\\r\\n/g, "\n")
      .replace(/\\n/g, "\n");


  const result = {};


  normalized
    .split("\n")
    .forEach((line) => {

      const separator =
        line.indexOf(":");


      /*
       * Ignore lines that are not
       * SIP headers.
       */

      if (separator <= 0) {
        return;
      }


      const name =
        line
          .slice(0, separator)
          .trim();


      const value =
        line
          .slice(separator + 1)
          .trim();


      /*
       * SIP permits duplicate headers,
       * e.g. P-Associated-URI.
       */

      if (result[name]) {

        if (Array.isArray(result[name])) {

          result[name].push(value);

        } else {

          result[name] = [
            result[name],
            value,
          ];

        }

      } else {

        result[name] = value;

      }

    });


  return result;
}


/* =========================================================
   HEADER COMPARISON
   ========================================================= */

function compareHeaders(
  previous,
  current
) {

  const names =
    new Set([
      ...Object.keys(previous),
      ...Object.keys(current),
    ]);


  const differences = [];


  for (const name of names) {

    const previousValue =
      normalizeHeaderValue(
        previous[name]
      );


    const currentValue =
      normalizeHeaderValue(
        current[name]
      );


    /*
     * Header didn't change.
     */

    if (
      previousValue ===
      currentValue
    ) {
      continue;
    }


    let changeType =
      "CHANGED";


    if (!previous[name]) {

      changeType =
        "ADDED";

    } else if (!current[name]) {

      changeType =
        "REMOVED";

    }


    differences.push({
      name,
      previous:
        previousValue ||
        "Not present",
      current:
        currentValue ||
        "Not present",
      changeType,
    });

  }


  /*
   * Put important IMS headers
   * at the top.
   */

  const priority = [
    "Authorization",
    "Contact",
    "Path",
    "Require",
    "P-Access-Network-Info",
    "P-Visited-Network-ID",
    "Content-Type",
    "Content-Length",
    "Supported",
    "Feature-Caps",
    "P-Charging-Vector",
  ];


  differences.sort(
    (a, b) => {

      const aIndex =
        priority.indexOf(a.name);

      const bIndex =
        priority.indexOf(b.name);


      if (
        aIndex === -1 &&
        bIndex === -1
      ) {
        return a.name.localeCompare(
          b.name
        );
      }


      if (aIndex === -1) {
        return 1;
      }


      if (bIndex === -1) {
        return -1;
      }


      return aIndex - bIndex;

    }
  );


  return differences;
}


/* =========================================================
   NORMALIZE HEADER VALUES
   ========================================================= */

function normalizeHeaderValue(value) {

  if (Array.isArray(value)) {

    return value.join(
      " | "
    );

  }


  return String(
    value ?? ""
  ).trim();
}


export default RegisterComparison;
