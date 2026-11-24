"use strict";

const byId = (id) => document.getElementById(id);
const number = new Intl.NumberFormat();
const decimal = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const form = byId("analysis");
const drop = byId("drop");
const input = byId("capture");
const download = byId("download");
const status = byId("status");
const limit = 16 * 1024 * 1024;
let selectedFile = null;
let downloadUrl = null;

function formatBytes(bytes) {
  if (bytes >= 1024 ** 2) return decimal.format(bytes / 1024 ** 2) + " MiB";
  if (bytes >= 1024) return decimal.format(bytes / 1024) + " KiB";
  return number.format(bytes) + " B";
}

function note(text, error = false) {
  status.textContent = text;
  status.hidden = !text;
  status.classList.toggle("error", error);
}

function selectFile(file) {
  if (file && (!/\.pcap$/i.test(file.name) || file.size < 24 || file.size > limit)) {
    selectedFile = null;
    input.value = "";
    note("Choose a .pcap file between 24 bytes and 16 MiB.", true);
  } else {
    selectedFile = file;
    note("");
  }
  byId("file-name").textContent = selectedFile?.name || "Choose or drop a PCAP";
  byId("file-size").textContent = selectedFile ? formatBytes(selectedFile.size) : "Ethernet PCAP · up to 16 MiB";
}

input.addEventListener("change", () => {
  if (input.files.length) selectFile(input.files[0]);
});
drop.addEventListener("dragover", (event) => {
  event.preventDefault();
  drop.classList.add("dragover");
});
drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
drop.addEventListener("drop", (event) => {
  event.preventDefault();
  drop.classList.remove("dragover");
  if (!byId("inputs").disabled && event.dataTransfer.files.length) {
    input.value = "";
    selectFile(event.dataTransfer.files[0]);
  }
});

function renderReport(report, name) {
  byId("result-source").textContent = name;
  byId("total").textContent = number.format(report.total_packets);
  byId("forwarded").textContent = number.format(report.forwarded);
  byId("dropped").textContent = number.format(report.dropped);
  byId("bytes").textContent = formatBytes(report.total_bytes);
  byId("protocols").textContent = number.format(report.tcp_packets) + " TCP · " + number.format(report.udp_packets) + " UDP";

  const applications = Object.entries(report.applications).sort(([a, countA], [b, countB]) =>
    countB - countA || a.localeCompare(b)
  );
  byId("apps-empty").hidden = applications.length > 0;
  byId("apps-empty").textContent = "The analyzer found no classifiable packets.";
  byId("applications").replaceChildren(...applications.map(([app, count]) => {
    const row = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = app;
    const bar = document.createElement("progress");
    bar.max = report.total_packets || 1;
    bar.value = count;
    bar.setAttribute("aria-label", app + " share of analyzed packets");
    const value = document.createElement("small");
    value.textContent = number.format(count);
    row.append(label, bar, value);
    return row;
  }));

  const table = byId("domains");
  table.replaceChildren();
  const domains = report.domains.sort((a, b) => a.name.localeCompare(b.name));
  byId("domains-empty").textContent = "No TLS SNI or HTTP Host names were detected.";
  byId("domains-empty").hidden = domains.length > 0;
  byId("domain-table").hidden = !domains.length;
  const fragment = document.createDocumentFragment();
  for (const domain of domains) {
    const row = document.createElement("tr");
    row.insertCell().textContent = domain.name;
    row.insertCell().textContent = domain.application;
    fragment.append(row);
  }
  table.append(fragment);
}

function setDownload(base64, name) {
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = URL.createObjectURL(new Blob([bytes], { type: "application/vnd.tcpdump.pcap" }));
  download.href = downloadUrl;
  download.download = name.replace(/\.pcap$/i, "") + "-filtered.pcap";
  download.hidden = false;
}

async function run(sample) {
  const file = selectedFile;
  if (!sample && !file) {
    note("Choose a capture or analyze the bundled sample.", true);
    input.focus();
    return;
  }
  const query = new URLSearchParams();
  for (const [field, value] of new FormData(form)) {
    if (value.trim()) query.set(field, value.trim());
  }
  if (sample) query.set("sample", "1");
  const name = sample ? "test_dpi.pcap" : file.name;
  const inputs = byId("inputs");
  inputs.disabled = true;
  note("Analyzing " + name + "…");
  try {
    const response = await fetch("/api/analyze?" + query, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: sample ? "" : file,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Analysis failed.");
    setDownload(result.capture, name);
    renderReport(result.report, name);
    note("Analysis complete.");
  } catch (error) {
    note(error.message || "Could not reach the analyzer.", true);
  } finally {
    inputs.disabled = false;
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  run(false);
});
byId("sample").addEventListener("click", () => run(true));
