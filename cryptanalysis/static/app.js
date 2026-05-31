const endpoints = {
  signature: "/analysis/signature-forgery",
  passwords: "/analysis/password-attacks",
  replay: "/analysis/replay",
};

const imageEndpoints = {
  metadata: "/analysis/image/metadata-format",
  pixels: "/analysis/image/pixel-sensitivity",
  certificate: "/analysis/image/certificate-forgery",
};

document.querySelectorAll("button[data-analysis]").forEach((button) => {
  button.addEventListener("click", () => runSingle(button.dataset.analysis, button));
});

document.querySelector("#run-all").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  setBusy(button, true, "Running...");
  setStatus("Running all");
  try {
    const data = await postJson("/analysis/run-all");
    renderSignature(data.results.signature_forgery);
    renderPasswords(data.results.password_attacks);
    renderReplay(data.results.replay_attack);
    renderMetadata(data.results.image_metadata_and_format);
    renderPixels(data.results.image_pixel_sensitivity);
    renderCertificate(data.results.image_certificate_forgery);
    showRaw(data);
    setStatus(`Complete in ${data.duration_ms} ms`);
  } catch (error) {
    showRaw(error.message);
    setStatus("Error");
  } finally {
    setBusy(button, false, "Run All Analyses");
  }
});

document.querySelector("#run-image-all").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  setBusy(button, true, "Running...");
  setStatus("Running image analyses");
  try {
    const data = await postJson("/analysis/image/run-all");
    renderMetadata(data.results.metadata_and_format);
    renderPixels(data.results.pixel_sensitivity);
    renderCertificate(data.results.certificate_forgery);
    showRaw(data);
    setStatus(`Image complete in ${data.duration_ms} ms`);
  } catch (error) {
    showRaw(error.message);
    setStatus("Error");
  } finally {
    setBusy(button, false, "Run Image Analyses");
  }
});

document.querySelectorAll("button[data-image-analysis]").forEach((button) => {
  button.addEventListener("click", () => runImageSingle(button.dataset.imageAnalysis, button));
});

async function runSingle(type, button) {
  setBusy(button, true, "Running...");
  setStatus("Running");
  try {
    const data = await postJson(endpoints[type]);
    if (type === "signature") renderSignature(data);
    if (type === "passwords") renderPasswords(data);
    if (type === "replay") renderReplay(data);
    showRaw(data);
    setStatus("Complete");
  } catch (error) {
    showRaw(error.message);
    setStatus("Error");
  } finally {
    setBusy(button, false, "Run Attack");
  }
}

async function runImageSingle(type, button) {
  setBusy(button, true, "Running...");
  setStatus("Running image analysis");
  try {
    const data = await postJson(imageEndpoints[type]);
    if (type === "metadata") renderMetadata(data);
    if (type === "pixels") renderPixels(data);
    if (type === "certificate") renderCertificate(data);
    showRaw(data);
    setStatus("Complete");
  } catch (error) {
    showRaw(error.message);
    setStatus("Error");
  } finally {
    setBusy(button, false, "Run Attack");
  }
}

async function postJson(endpoint) {
  const response = await fetch(endpoint, { method: "POST" });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }
  return data;
}

function renderSignature(data) {
  document.querySelector("#sig-original").innerHTML = kvList({
    Subject: data.original_claims.sub,
    Role: data.original_claims.role,
    Expires: formatTime(data.original_claims.exp),
    JTI: data.original_claims.jti,
  });

  document.querySelector("#sig-attack").innerHTML = kvList({
    "Changed role": `${data.original_claims.role} -> ${data.tampered_claims_attempted.role}`,
    "Changed expiry": `${formatTime(data.original_claims.exp)} -> ${formatTime(data.tampered_claims_attempted.exp)}`,
    "Signature action": "Reused original signature",
    "Random key attempts": data.random_key_forgery.attempts,
  });

  const accepted = data.tampered_token_verification.accepted;
  setResult(
    "#sig-result",
    accepted ? "Tampered token accepted" : "Tampered token rejected",
    accepted ? "bad" : "good",
    accepted ? "The attack unexpectedly passed." : data.tampered_token_verification.error
  );

  document.querySelector("#sig-analysis").innerHTML = paragraphs([
    data.summary,
    `Random HMAC forgeries: ${data.random_key_forgery.successful_random_forges}.`,
    data.length_extension_note.cat_signature,
  ]);
}

function renderPasswords(data) {
  document.querySelector("#pass-original").innerHTML = table(
    ["User", "Plain SHA-256 hash"],
    Object.entries(data.plain_sha256.stored_hashes).map(([user, hash]) => [user, shortHash(hash)])
  );

  document.querySelector("#pass-attack").innerHTML = table(
    ["User", "Cracked password"],
    Object.entries(data.plain_sha256.cracked).map(([user, password]) => [user, password])
  );

  const saltedRows = data.users.map((user) => [
    user,
    shortHash(data.salted_sha256.stored_hashes[user]),
    data.salted_sha256.rainbow_table_reuse_cracked[user] || "Not cracked by reused table",
  ]);
  document.querySelector("#pass-result").innerHTML = table(
    ["User", "Salted hash", "Rainbow reuse"],
    saltedRows
  );

  document.querySelector("#pass-analysis").innerHTML = paragraphs([
    data.summary,
    `Unsalted cracked: ${data.plain_sha256.cracked_count} of ${data.users.length}.`,
    `Salted rainbow-table reuse cracked: ${Object.keys(data.salted_sha256.rainbow_table_reuse_cracked).length}.`,
    `Salted dictionary recomputation cost: ${data.salted_sha256.hash_computations} hash operations.`,
  ]);
}

function renderReplay(data) {
  const claims = data.initial_access.claims;
  document.querySelector("#replay-original").innerHTML = kvList({
    Subject: claims.sub,
    Role: claims.role,
    "Initial access": data.initial_access.accepted ? "Accepted" : "Rejected",
    Expires: formatTime(claims.exp),
    JTI: claims.jti,
  });

  document.querySelector("#replay-attack").innerHTML = kvList({
    Action: "Logout / revoke token",
    "Revoked JTI": data.revoke_result.jti,
    "Replay input": "Exact same token",
    "Signature still parses": data.cryptographic_claims_before_revoke.jti === data.revoke_result.jti ? "Yes" : "No",
  });

  setResult(
    "#replay-result",
    data.replay_after_revoke.accepted ? "Replay accepted" : "Replay rejected",
    data.replay_after_revoke.accepted ? "bad" : "good",
    data.replay_after_revoke.accepted ? "Revocation failed." : data.replay_after_revoke.error
  );

  document.querySelector("#replay-analysis").innerHTML = paragraphs([
    data.summary,
    `With revocation: replay accepted = ${data.replay_after_revoke.accepted}.`,
    `Without revocation: replay accepted = ${data.replay_without_revocation.accepted}.`,
    "The blacklist is authorization state outside the token signature.",
  ]);
}

function renderMetadata(data) {
  document.querySelector("#meta-original").innerHTML = kvList({
    Author: data.signed_image.author,
    "Image ID": data.signed_image.image_id,
    "Payload bytes": data.signed_image.payload_bytes,
    "Carrier pixels": data.signed_image.carrier_pixels,
  });

  document.querySelector("#meta-attack").innerHTML = kvList({
    "Metadata attack": data.metadata_stripping.change,
    "Format attack": data.jpeg_conversion.change,
    "Storage assumption": "PNG/lossless required",
  });

  const stripOk = data.metadata_stripping.survived;
  const jpegOk = data.jpeg_conversion.survived;
  setResult(
    "#meta-result",
    stripOk && !jpegOk ? "Metadata survives, JPEG breaks signature" : "Unexpected conversion result",
    stripOk && !jpegOk ? "good" : "warn",
    `Metadata strip: ${data.metadata_stripping.after_strip_verification}; JPEG round trip: ${data.jpeg_conversion.after_conversion_verification}`
  );

  document.querySelector("#meta-analysis").innerHTML = paragraphs([
    data.summary,
    `Metadata stripping survived: ${stripOk}.`,
    `JPEG conversion survived: ${jpegOk}.`,
    data.jpeg_conversion.reason,
  ]);
}

function renderPixels(data) {
  document.querySelector("#pixel-original").innerHTML = kvList({
    "Image ID": data.baseline.image_id,
    Verification: data.baseline.verification,
    "Hash prefix": shortHash(data.baseline.expected_hash),
  });

  document.querySelector("#pixel-attack").innerHTML = table(
    ["Scenario", "Pixels changed", "Verification"],
    data.modifications.map((item) => [item.scenario, item.modified_pixels, item.verification])
  );

  document.querySelector("#pixel-result").innerHTML = table(
    ["Scenario", "Hamming distance", "Hash valid"],
    data.modifications.map((item) => [
      item.scenario,
      `${item.hamming_distance_bits} / 256 bits`,
      String(item.pixel_hash_valid),
    ])
  );

  document.querySelector("#pixel-analysis").innerHTML = paragraphs([
    data.summary,
    data.avalanche_note,
    "Every tested modification was rejected because the canonical pixel hash changed.",
  ]);
}

function renderCertificate(data) {
  document.querySelector("#cert-original").innerHTML = kvList({
    Author: data.extracted_certificate.author,
    "Image ID": data.extracted_certificate.image_id,
    Timestamp: formatTime(data.extracted_certificate.timestamp),
    "Hash prefix": shortHash(data.extracted_certificate.hash),
  });

  document.querySelector("#cert-attack").innerHTML = kvList({
    Change: data.forgery.change,
    "Signature strategy": data.forgery.signature_strategy,
    "Payload bytes": data.forgery.payload_bytes,
    "Forged author": data.forged_certificate_attempt.author,
  });

  const accepted = data.verification.status === "AUTHENTIC";
  setResult(
    "#cert-result",
    accepted ? "Forged certificate accepted" : "Forged certificate rejected",
    accepted ? "bad" : "good",
    data.verification.reason
  );

  document.querySelector("#cert-analysis").innerHTML = paragraphs([
    data.summary,
    `HMAC valid: ${data.verification.hmac_valid}.`,
    data.takeaway,
  ]);
}

function kvList(values) {
  return Object.entries(values)
    .map(([key, value]) => `<div class="kv"><span>${escapeHtml(key)}</span><strong>${escapeHtml(String(value))}</strong></div>`)
    .join("");
}

function table(headers, rows) {
  return `
    <table>
      <thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>
      <tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(String(cell))}</td>`).join("")}</tr>`).join("")}</tbody>
    </table>
  `;
}

function paragraphs(lines) {
  return lines.map((line) => `<p>${escapeHtml(line)}</p>`).join("");
}

function setResult(selector, title, tone, detail) {
  const el = document.querySelector(selector);
  el.className = "result-box " + tone;
  el.innerHTML = `<div>${escapeHtml(title)}</div><p>${escapeHtml(detail)}</p>`;
}

function showRaw(value) {
  document.querySelector("#raw-output").textContent =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

function setStatus(text) {
  document.querySelector("#run-status").textContent = text;
}

function shortHash(hash) {
  return `${hash.slice(0, 14)}...${hash.slice(-10)}`;
}

function formatTime(epochSeconds) {
  return new Date(epochSeconds * 1000).toLocaleTimeString();
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
