const logInput = document.querySelector("#log-input");
const analyseButton = document.querySelector("#analyse-button");
const sampleButton = document.querySelector("#sample-button");
const clearButton = document.querySelector("#clear-button");
const lineCount = document.querySelector("#line-count");
const message = document.querySelector("#message");
const results = document.querySelector("#results");

function setMessage(text, type = "") {
  message.textContent = text;
  message.className = `message ${type}`.trim();
}

function updateLineCount() {
  const count = logInput.value.split("\n").filter((line) => line.trim()).length;
  lineCount.textContent = `${count} ${count === 1 ? "line" : "lines"}`;
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderMetrics(data) {
  const metrics = document.querySelector("#metrics");
  const values = [
    ["Parsed requests", data.summary.parsed_lines],
    ["Unique sources", data.summary.unique_ips],
    ["Security alerts", data.alerts.length],
    ["Risk score", `${data.risk.score}/100`],
  ];
  metrics.replaceChildren(
    ...values.map(([label, value]) => {
      const card = makeElement("div", "metric");
      card.append(makeElement("span", "metric-label", label));
      card.append(makeElement("strong", "metric-value", String(value)));
      return card;
    }),
  );
}

function renderStatuses(data) {
  const container = document.querySelector("#status-bars");
  const groups = data.summary.status_groups;
  const maxValue = Math.max(...Object.values(groups), 1);
  const rows = Object.entries(groups)
    .filter(([, count]) => count > 0)
    .map(([group, count]) => {
      const row = makeElement("div", "status-row");
      const track = makeElement("div", "bar-track");
      const fill = makeElement("div", "bar-fill");
      fill.style.width = `${Math.max((count / maxValue) * 100, 4)}%`;
      track.append(fill);
      row.append(makeElement("span", "", group), track, makeElement("span", "", String(count)));
      return row;
    });
  container.replaceChildren(...rows);
  document.querySelector("#parse-quality").textContent =
    `${data.summary.parsed_lines}/${data.summary.total_lines} lines parsed`;
}

function renderPaths(data) {
  const container = document.querySelector("#path-list");
  const rows = data.summary.top_paths.map((item) => {
    const row = makeElement("div", "path-row");
    row.append(makeElement("code", "", item.path), makeElement("span", "", String(item.count)));
    return row;
  });
  container.replaceChildren(...rows);
}

function renderAlerts(data) {
  const container = document.querySelector("#alert-list");
  document.querySelector("#alert-count").textContent =
    `${data.alerts.length} ${data.alerts.length === 1 ? "finding" : "findings"}`;

  if (!data.alerts.length) {
    container.replaceChildren(
      makeElement("div", "empty-alerts", "No configured rule matched this sample."),
    );
    return;
  }

  const cards = data.alerts.map((alert) => {
    const card = makeElement("article", "alert-card");
    card.append(makeElement("span", `severity ${alert.severity}`, alert.severity));
    const body = makeElement("div", "alert-body");
    body.append(makeElement("h3", "alert-name", alert.type.replaceAll("_", " ")));
    body.append(makeElement("p", "alert-description", alert.description));
    body.append(makeElement("p", "alert-evidence", `Evidence: ${alert.evidence.join(" · ")}`));
    card.append(body);
    card.append(
      makeElement("div", "alert-source", `${alert.source_ip}\n${alert.count} match${alert.count === 1 ? "" : "es"}`),
    );
    return card;
  });
  container.replaceChildren(...cards);
}

function renderResults(data) {
  renderMetrics(data);
  renderStatuses(data);
  renderPaths(data);
  renderAlerts(data);

  const badge = document.querySelector("#risk-badge");
  badge.className = `risk-badge ${data.risk.level}`;
  badge.textContent = `${data.risk.level} risk · ${data.risk.score}`;
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function analyseLogs() {
  if (!logInput.value.trim()) {
    setMessage("Paste access logs or load the sample first.", "error");
    logInput.focus();
    return;
  }

  analyseButton.disabled = true;
  setMessage("Analysing the bounded sample…");
  try {
    const response = await fetch("/api/analyse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log_text: logInput.value }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Analysis failed (${response.status})`);
    renderResults(payload);
    const rejected = payload.summary.rejected_lines;
    setMessage(
      rejected ? `Analysis complete; ${rejected} unsupported line${rejected === 1 ? " was" : "s were"} skipped.` : "Analysis complete.",
      "success",
    );
  } catch (error) {
    setMessage(error.message, "error");
  } finally {
    analyseButton.disabled = false;
  }
}

async function loadSample() {
  sampleButton.disabled = true;
  setMessage("Loading the synthetic sample…");
  try {
    const response = await fetch("/api/sample");
    const payload = await response.json();
    if (!response.ok) throw new Error("Could not load the sample");
    logInput.value = payload.log_text;
    updateLineCount();
    setMessage("Synthetic sample loaded. Select Analyse logs.", "success");
  } catch (error) {
    setMessage(error.message, "error");
  } finally {
    sampleButton.disabled = false;
  }
}

async function checkHealth() {
  const state = document.querySelector("#service-state");
  try {
    const response = await fetch("/health");
    if (!response.ok) throw new Error();
    const payload = await response.json();
    state.textContent = `Service healthy · ${payload.version.slice(0, 8)}`;
    state.className = "service-state healthy";
  } catch {
    state.textContent = "Service unavailable";
    state.className = "service-state unhealthy";
  }
}

logInput.addEventListener("input", updateLineCount);
analyseButton.addEventListener("click", analyseLogs);
sampleButton.addEventListener("click", loadSample);
clearButton.addEventListener("click", () => {
  logInput.value = "";
  updateLineCount();
  results.hidden = true;
  setMessage("");
  logInput.focus();
});

checkHealth();
updateLineCount();
