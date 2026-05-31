const signFile = document.querySelector("#sign-file");
const verifyFile = document.querySelector("#verify-file");
const author = document.querySelector("#author");
const signPreview = document.querySelector("#sign-preview");
const signedPreview = document.querySelector("#signed-preview");
const verifyPreview = document.querySelector("#verify-preview");
const signOutput = document.querySelector("#sign-output");
const verifyOutput = document.querySelector("#verify-output");
const downloadLink = document.querySelector("#download-link");
const resultBadge = document.querySelector("#result-badge");

let signedObjectUrl = "";

document.querySelector("#sign-btn").addEventListener("click", signImage);
document.querySelector("#verify-btn").addEventListener("click", verifyImage);
document.querySelector("#inspect-btn").addEventListener("click", inspectImage);

bindPreview(signFile, signPreview);
bindPreview(verifyFile, verifyPreview);
bindDropZone(document.querySelector("#sign-drop"), signFile, signPreview);
bindDropZone(document.querySelector("#verify-drop"), verifyFile, verifyPreview);

async function signImage() {
  if (!signFile.files[0]) {
    show(signOutput, "Choose an image to sign.");
    return;
  }

  const form = new FormData();
  form.append("file", signFile.files[0]);
  form.append("author", author.value || "anonymous");

  const button = document.querySelector("#sign-btn");
  setBusy(button, true, "Signing...");
  try {
    const response = await fetch("/image/sign", { method: "POST", body: form });
    if (!response.ok) {
      throw new Error(await responseText(response));
    }
    const blob = await response.blob();
    if (signedObjectUrl) URL.revokeObjectURL(signedObjectUrl);
    signedObjectUrl = URL.createObjectURL(blob);
    signedPreview.src = signedObjectUrl;
    downloadLink.href = signedObjectUrl;
    downloadLink.classList.remove("disabled");
    show(signOutput, {
      status: "SIGNED",
      image_id: response.headers.get("X-Image-Id"),
      algorithm: response.headers.get("X-Signature-Algorithm"),
      output: "Download the returned PNG before verification.",
    });
  } catch (error) {
    show(signOutput, error.message);
  } finally {
    setBusy(button, false, "Sign Image");
  }
}

async function verifyImage() {
  if (!verifyFile.files[0]) {
    show(verifyOutput, "Choose an image to verify.");
    setBadge("No result", "neutral");
    return;
  }

  const button = document.querySelector("#verify-btn");
  setBusy(button, true, "Verifying...");
  try {
    const result = await uploadJson("/image/verify", verifyFile.files[0]);
    setBadge(result.status, result.status.toLowerCase());
    show(verifyOutput, result);
  } catch (error) {
    setBadge("Error", "tampered");
    show(verifyOutput, error.message);
  } finally {
    setBusy(button, false, "Verify");
  }
}

async function inspectImage() {
  if (!verifyFile.files[0]) {
    show(verifyOutput, "Choose an image to inspect.");
    return;
  }

  const button = document.querySelector("#inspect-btn");
  setBusy(button, true, "Inspecting...");
  try {
    const result = await uploadJson("/image/inspect", verifyFile.files[0]);
    setBadge("Inspected", "neutral");
    show(verifyOutput, result);
  } catch (error) {
    setBadge("Unsigned", "unsigned");
    show(verifyOutput, error.message);
  } finally {
    setBusy(button, false, "Inspect");
  }
}

async function uploadJson(path, file) {
  const form = new FormData();
  form.append("file", file);
  const response = await fetch(path, { method: "POST", body: form });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }
  return data;
}

async function responseText(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const data = await response.json();
    return data.detail || JSON.stringify(data);
  }
  return await response.text();
}

function bindPreview(input, image) {
  input.addEventListener("change", () => {
    const file = input.files[0];
    if (!file) return;
    image.src = URL.createObjectURL(file);
  });
}

function bindDropZone(zone, input, image) {
  zone.addEventListener("dragover", (event) => {
    event.preventDefault();
    zone.classList.add("dragging");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragging"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("dragging");
    if (!event.dataTransfer.files.length) return;
    input.files = event.dataTransfer.files;
    image.src = URL.createObjectURL(event.dataTransfer.files[0]);
  });
}

function setBadge(text, type) {
  resultBadge.textContent = text;
  resultBadge.className = "badge " + type;
}

function show(target, value) {
  target.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}
