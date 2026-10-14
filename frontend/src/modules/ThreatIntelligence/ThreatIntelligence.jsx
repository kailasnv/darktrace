import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom"; // INTEGRATION
import "./ThreatIntelligence.css";
import { getAlerts, reviewAlert, alertToThreat } from "../../api"; // BACKEND
import { useToast } from "../../components/ui"; // BACKEND

const initialThreats = [
  {
    id: 1,
    name: "BlackCat Ransomware Infrastructure",
    severity: "Critical",
    ioc: "abcxyz.onion",
    type: "Domain",
    source: "Dark Web Crawler",
    detected: "5 min ago",
    detectedAt: "2026-10-05T14:25:00",
    status: "Active",
    description:
      "Ransomware-related infrastructure was detected on the dark web. The domain appears to advertise access to compromised enterprise networks.",
  },
  {
    id: 2,
    name: "Credential Harvesting Server",
    severity: "High",
    ioc: "185.220.101.42",
    type: "IP",
    source: "Threat Feed Alpha",
    detected: "40 min ago",
    detectedAt: "2026-10-05T13:50:00",
    status: "Investigating",
    description:
      "This IP address has been associated with credential harvesting pages and repeated authentication attacks.",
  },
  {
    id: 3,
    name: "Stealer Malware Payload",
    severity: "High",
    ioc: "9f3a7c2d8e1b4a6f",
    type: "Hash",
    source: "Malware Bazaar",
    detected: "1 hr ago",
    detectedAt: "2026-10-05T12:35:00",
    status: "Active",
    description:
      "The file hash matches a known information-stealing malware sample targeting browser credentials.",
  },
  {
    id: 4,
    name: "Phishing Campaign Landing Page",
    severity: "Medium",
    ioc: "secure-login-check.com",
    type: "URL",
    source: "OpenCTI",
    detected: "2 hrs ago",
    detectedAt: "2026-10-05T11:20:00",
    status: "Monitoring",
    description:
      "A phishing page impersonating an enterprise login portal was identified and added to monitoring.",
  },
  {
    id: 5,
    name: "Botnet Command Server",
    severity: "Critical",
    ioc: "91.214.124.77",
    type: "IP",
    source: "Dark Web Crawler",
    detected: "3 hrs ago",
    detectedAt: "2026-10-05T10:45:00",
    status: "Active",
    description:
      "The address is linked to command-and-control traffic from a distributed botnet cluster.",
  },
  {
    id: 6,
    name: "Suspicious Exfiltration Domain",
    severity: "Medium",
    ioc: "upload-node.net",
    type: "Domain",
    source: "Threat Feed Alpha",
    detected: "4 hrs ago",
    detectedAt: "2026-10-05T09:30:00",
    status: "Investigating",
    description:
      "The domain appears to receive compressed archives uploaded from compromised hosts.",
  },
  {
    id: 7,
    name: "Remote Access Trojan Sample",
    severity: "High",
    ioc: "4c7d1a9ef02b8c11",
    type: "Hash",
    source: "VirusTotal",
    detected: "16 hrs ago",
    detectedAt: "2026-10-04T22:10:00",
    status: "Active",
    description:
      "A remote access trojan sample was detected with capabilities for persistence and remote command execution.",
  },
  {
    id: 8,
    name: "Tracking Domain",
    severity: "Low",
    ioc: "cdn-statistics.org",
    type: "Domain",
    source: "OpenCTI",
    detected: "19 hrs ago",
    detectedAt: "2026-10-04T19:40:00",
    status: "Monitoring",
    description:
      "The domain has weak indicators of malicious tracking activity and requires additional observation.",
  },
  {
    id: 9,
    name: "Malicious Redirect Chain",
    severity: "Medium",
    ioc: "hxxps://redirect-check[.]site/a4",
    type: "URL",
    source: "URLhaus",
    detected: "22 hrs ago",
    detectedAt: "2026-10-04T16:15:00",
    status: "Resolved",
    description:
      "A redirect chain was found leading users from an advertising page to a malware distribution site.",
  },
  {
    id: 10,
    name: "Known Exploit Delivery Host",
    severity: "Critical",
    ioc: "103.76.12.19",
    type: "IP",
    source: "Threat Feed Alpha",
    detected: "1 day ago",
    detectedAt: "2026-10-04T12:00:00",
    status: "Active",
    description:
      "The host has delivered exploit kits targeting unpatched web applications.",
  },
];

const severityOrder = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

const trendHeights = {
  total: [35, 64, 43, 78, 52, 92, 68],
  critical: [78, 44, 88, 53, 76, 38, 69],
  high: [38, 49, 63, 86, 73, 82, 94],
  medium: [90, 72, 55, 42, 61, 49, 35],
  low: [42, 58, 39, 69, 47, 62, 54],
};

function Sparkline({ variant }) {
  return (
    <div className={`stat-sparkline trend-${variant}`} aria-hidden="true">
      {trendHeights[variant].map((height, index) => (
        <span key={`${variant}-${index}`} style={{ height: `${height}%` }} />
      ))}
    </div>
  );
}

function SeverityBadge({ severity }) {
  return (
    <span className={`badge ${severity.toLowerCase()}`}>
      <span className="badge-dot" />
      {severity}
    </span>
  );
}

function ThreatCard({ threat, onSelect }) {
  return (
    <button
      type="button"
      className="threat-card"
      onClick={() => onSelect(threat)}
      aria-label={`Open details for ${threat.name}`}
    >
      <div className="threat-card-top">
        <div>
          <small>{threat.type} IOC</small>
          <h3>{threat.name}</h3>
        </div>

        <SeverityBadge severity={threat.severity} />
      </div>

      <div className="threat-data">
        <div>
          <small>IOC</small>
          <code>{threat.ioc}</code>
        </div>

        <div>
          <small>Source</small>
          <span>{threat.source}</span>
        </div>

        <div>
          <small>Detected</small>
          <span>{threat.detected}</span>
        </div>
      </div>

      <span className="card-arrow">↗</span>
    </button>
  );
}

function ThreatActivityChart({ threats }) {
  const now = Date.now();
  const values = Array(12).fill(0);
  threats.forEach((threat) => {
    const ageHours = (now - new Date(threat.detectedAt).getTime()) / (60 * 60 * 1000);
    if (Number.isFinite(ageHours) && ageHours >= 0 && ageHours < 24) values[11 - Math.floor(ageHours / 2)] += 1;
  });
  const maxValue = Math.max(...values, 1);
  const chartWidth = 600;
  const chartHeight = 180;

  const linePoints = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * chartWidth;
      const y = chartHeight - (value / maxValue) * chartHeight;
      return `${x},${y}`;
    })
    .join(" ");

  const areaPoints = `0,${chartHeight} ${linePoints} ${chartWidth},${chartHeight}`;

  const criticalCount = threats.filter(
    (threat) => threat.severity === "Critical"
  ).length;

  return (
    <section
      className="activity-panel"
      aria-label="Threat activity for the last 24 hours"
    >
      <div className="activity-heading">
        <div>
          <p className="eyebrow">TELEMETRY OVERVIEW</p>
          <h2>Threat activity — last 24 hours</h2>
        </div>

        <div className="activity-summary">
          <span>{threats.length} indicators</span>
          <span>{criticalCount} critical</span>
        </div>
      </div>

      <div className="activity-chart">
        <div className="activity-y-axis">
          <span>HIGH</span>
          <span>MED</span>
          <span>LOW</span>
        </div>

        <div className="activity-plot">
          <div className="activity-grid-line line-one" />
          <div className="activity-grid-line line-two" />
          <div className="activity-grid-line line-three" />

          <svg
            className="activity-line"
            viewBox={`0 0 ${chartWidth} ${chartHeight}`}
            preserveAspectRatio="none"
            role="img"
            aria-label="Threat activity trend"
          >
            <defs>
              <linearGradient id="activityFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#35d8ef" stopOpacity="0.25" />
                <stop offset="100%" stopColor="#35d8ef" stopOpacity="0" />
              </linearGradient>
            </defs>

            <polygon points={areaPoints} fill="url(#activityFill)" />

            <polyline
              points={linePoints}
              fill="none"
              stroke="#55d9dc"
              strokeWidth="3"
              vectorEffect="non-scaling-stroke"
            />

            {values.map((value, index) => {
              const x = (index / (values.length - 1)) * chartWidth;
              const y = chartHeight - (value / maxValue) * chartHeight;

              return (
                <circle
                  key={`${value}-${index}`}
                  cx={x}
                  cy={y}
                  r="3"
                  fill="#071016"
                  stroke="#55d9dc"
                  strokeWidth="2"
                  vectorEffect="non-scaling-stroke"
                />
              );
            })}
          </svg>

          <div className="activity-x-axis">
            <span>00</span>
            <span>04</span>
            <span>08</span>
            <span>12</span>
            <span>16</span>
            <span>20</span>
            <span>24</span>
          </div>
        </div>
      </div>
    </section>
  );
}

function ThreatDetails({
  threat,
  onClose,
  onReviewed,
  copied,
  onCopy,
}) {
  if (!threat) {
    return null;
  }

  const isReviewed = threat.status === "Reviewed";

  /* INTEGRATION: portal to <body> (base README rule 2: perspective/backdrop-filter trap position:fixed) */
  return createPortal(
    <div className="modal-backdrop" onClick={onClose}>
      <aside
        className="details-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="details-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="details-header">
          <div>
            <p className="eyebrow">THREAT DETAILS</p>
            <h2 id="details-title">{threat.name}</h2>
          </div>

          <button
            type="button"
            className="close-button"
            onClick={onClose}
            aria-label="Close threat details"
          >
            ×
          </button>
        </div>

        <div className="details-badges">
          <SeverityBadge severity={threat.severity} />
          <span className={`status-badge ${isReviewed ? "reviewed" : ""}`}>
            {threat.status}
          </span>
        </div>

        <div className="details-grid">
          <div className="ioc-detail">
            <small>IOC</small>

            <div className="ioc-copy-row">
              <code>{threat.ioc}</code>

              <button
                type="button"
                className="copy-button"
                onClick={() => onCopy(threat.ioc)}
              >
                {copied === threat.ioc ? "COPIED" : "COPY"}
              </button>
            </div>
          </div>

          <div>
            <small>IOC Type</small>
            <span>{threat.type}</span>
          </div>

          <div>
            <small>Source</small>
            <span>{threat.source}</span>
          </div>

          <div>
            <small>Detection Time</small>
            <span>{threat.detected}</span>
          </div>
        </div>

        <div className="description-box">
          <small>Description</small>
          <p>{threat.description}</p>
        </div>

        <button
          type="button"
          className={`review-button ${isReviewed ? "is-reviewed" : ""}`}
          disabled={isReviewed}
          onClick={() => onReviewed(threat.id)}
          title="Marks this alert reviewed and saves it via PATCH /api/v1/alerts/{id}"
        >
          {isReviewed ? "Reviewed" : "Mark reviewed"}
        </button>
      </aside>
    </div>,
    document.body
  );
}

export default function ThreatIntelligence() {
  const toast = useToast();
  const [threats, setThreats] = useState([]);
  const [loadError, setLoadError] = useState(false);

  // BACKEND: load alerts from GET /api/v1/alerts, refresh every 30 s.
  // Review status now comes back from the server (PATCH /api/v1/alerts/{id}
  // persists it), so there's no client-side "reviewed" tracking to merge in.
  useEffect(() => {
    let alive = true;
    let warned = false;
    const load = async () => {
      try {
        const data = await getAlerts();
        if (!alive) return;
        setThreats(data.map(alertToThreat));
        setLoadError(false);
        setLastUpdate(0);
      } catch {
        if (!alive) return;
        setThreats([]);
        setLoadError(true);
        if (!warned) {
          warned = true;
          toast.warning("Backend unreachable - no alert data to display");
        }
      }
    };
    load();
    const timer = window.setInterval(load, 30000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("All");
  const [type, setType] = useState("All");
  const [source, setSource] = useState("All");
  const [sort, setSort] = useState("Newest");
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [copied, setCopied] = useState("");
  const [lastUpdate, setLastUpdate] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setLastUpdate((value) => value + 1);
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!selectedThreat) {
      return;
    }

    const currentThreat = threats.find(
      (threat) => threat.id === selectedThreat.id
    );

    setSelectedThreat(currentThreat || null);
  }, [threats, selectedThreat]);

  const sources = [...new Set(threats.map((threat) => threat.source))];
  const types = [...new Set(threats.map((threat) => threat.type))];

  const counts = {
    total: threats.length,
    critical: threats.filter((threat) => threat.severity === "Critical").length,
    high: threats.filter((threat) => threat.severity === "High").length,
    medium: threats.filter((threat) => threat.severity === "Medium").length,
    low: threats.filter((threat) => threat.severity === "Low").length,
  };

  const visibleThreats = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    const filtered = threats.filter((threat) => {
      const searchableText = [
        threat.name,
        threat.ioc,
        threat.source,
        threat.type,
        threat.status,
      ]
        .join(" ")
        .toLowerCase();

      const matchesSearch =
        normalizedSearch === "" || searchableText.includes(normalizedSearch);

      const matchesSeverity =
        severity === "All" || threat.severity === severity;

      const matchesType = type === "All" || threat.type === type;

      const matchesSource = source === "All" || threat.source === source;

      return matchesSearch && matchesSeverity && matchesType && matchesSource;
    });

    return [...filtered].sort((a, b) => {
      if (sort === "Oldest") {
        return new Date(a.detectedAt) - new Date(b.detectedAt);
      }

      if (sort === "Highest severity") {
        return severityOrder[b.severity] - severityOrder[a.severity];
      }

      return new Date(b.detectedAt) - new Date(a.detectedAt);
    });
  }, [search, severity, type, source, sort, threats]);

  const handleCopy = async (ioc) => {
    try {
      await navigator.clipboard.writeText(ioc);
      setCopied(ioc);
      window.setTimeout(() => setCopied(""), 1400);
    } catch {
      setCopied("");
    }
  };

  const handleReviewed = async (threatId) => {
    // Optimistic update -- the card flips to "Reviewed" immediately,
    // then we persist it. If the request fails, we roll the card back
    // and tell the analyst, rather than leaving a false "Reviewed" state.
    setThreats((currentThreats) =>
      currentThreats.map((threat) =>
        threat.id === threatId ? { ...threat, status: "Reviewed" } : threat
      )
    );

    try {
      await reviewAlert(threatId, { status: "Reviewed" });
    } catch {
      setThreats((currentThreats) =>
        currentThreats.map((threat) =>
          threat.id === threatId ? { ...threat, status: "Active" } : threat
        )
      );
      toast.warning("Could not save review status - try again");
    }
  };

  const resetFilters = () => {
    setSearch("");
    setSeverity("All");
    setType("All");
    setSource("All");
    setSort("Newest");
  };

  return (
    <main className="threat-page">
      <header className="threat-header">
        <div>
          <p className="eyebrow">DARKTRACE / INTELLIGENCE</p>
          <h1>Threat Intelligence</h1>
          <p>Monitor and investigate collected threat indicators.</p>
        </div>

        <div className="live-monitoring">
          <span className="live-status">
            <span className="live-dot" />
            {loadError ? "OFFLINE" : "LIVE"}
          </span>
          <small>{loadError ? "Backend unavailable" : `Last update: ${lastUpdate} sec ago`}</small>
        </div>
      </header>

      <section className="stats-grid" aria-label="Threat statistics">
        <div className="stat-card total">
          <span>Total threats</span>
          <strong>{counts.total}</strong>
          <Sparkline variant="total" />
        </div>

        <div className="stat-card critical">
          <span>Critical</span>
          <strong>{counts.critical}</strong>
          <Sparkline variant="critical" />
        </div>

        <div className="stat-card high">
          <span>High</span>
          <strong>{counts.high}</strong>
          <Sparkline variant="high" />
        </div>

        <div className="stat-card medium">
          <span>Medium</span>
          <strong>{counts.medium}</strong>
          <Sparkline variant="medium" />
        </div>

        <div className="stat-card low">
          <span>Low</span>
          <strong>{counts.low}</strong>
          <Sparkline variant="low" />
        </div>
      </section>

      <section className="filters" aria-label="Threat filters">
        <label className="search-box">
          <span>⌕</span>
          <input
            type="search"
            placeholder="Search threat, IOC or source..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>

        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          aria-label="Filter by severity"
        >
          <option value="All">Severity: All</option>
          <option value="Critical">Severity: Critical</option>
          <option value="High">Severity: High</option>
          <option value="Medium">Severity: Medium</option>
          <option value="Low">Severity: Low</option>
        </select>

        <select
          value={type}
          onChange={(event) => setType(event.target.value)}
          aria-label="Filter by IOC type"
        >
          <option value="All">Type: All</option>
          {types.map((item) => (
            <option key={item} value={item}>Type: {item}</option>
          ))}
        </select>

        <select
          value={source}
          onChange={(event) => setSource(event.target.value)}
          aria-label="Filter by source"
        >
          <option value="All">Source: All</option>
          {sources.map((item) => (
            <option key={item} value={item}>
              Source: {item}
            </option>
          ))}
        </select>

        <select
          value={sort}
          onChange={(event) => setSort(event.target.value)}
          aria-label="Sort threats"
        >
          <option value="Newest">Sort: Newest</option>
          <option value="Oldest">Sort: Oldest</option>
          <option value="Highest severity">
            Sort: Highest severity
          </option>
        </select>

        <button type="button" className="reset-button" onClick={resetFilters}>
          Reset
        </button>
      </section>

      <ThreatActivityChart threats={threats} />

      <div className="feed-heading">
        <div>
          <p className="eyebrow">DETECTED INDICATORS</p>
          <h2>Threat feed</h2>
        </div>

        <span>{visibleThreats.length} results</span>
      </div>

      <section className="threat-list" aria-live="polite">
        {visibleThreats.length > 0 ? (
          visibleThreats.map((threat) => (
            <ThreatCard
              key={threat.id}
              threat={threat}
              onSelect={setSelectedThreat}
            />
          ))
        ) : (
          <div className="empty-state">
            <span className="empty-icon">◌</span>
            <h3>No threats found</h3>
            <p>Try changing your search or reset the filters.</p>
            <button
              type="button"
              className="reset-button"
              onClick={resetFilters}
            >
              Clear filters
            </button>
          </div>
        )}
      </section>

      <ThreatDetails
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        onReviewed={handleReviewed}
        copied={copied}
        onCopy={handleCopy}
      />
    </main>
  );
}
