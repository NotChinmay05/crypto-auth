const state = {
  token: localStorage.getItem("roleauth.token") || "",
  claims: null,
  profile: null,
};

const els = {
  username: document.querySelector("#username"),
  password: document.querySelector("#password"),
  role: document.querySelector("#role"),
  department: document.querySelector("#department"),
  status: document.querySelector("#status"),
  sessionPill: document.querySelector("#session-pill"),
  tokenBox: document.querySelector("#token-box"),
  authLog: document.querySelector("#auth-log"),
  claimsOutput: document.querySelector("#claims-output"),
  profileUsername: document.querySelector("#profile-username"),
  profileRole: document.querySelector("#profile-role"),
  profileExp: document.querySelector("#profile-exp"),
  userCard: document.querySelector("#user-card"),
  adminCard: document.querySelector("#admin-card"),
  userState: document.querySelector("#user-state"),
  adminState: document.querySelector("#admin-state"),
  userActionBtn: document.querySelector("#user-action-btn"),
  adminActionBtn: document.querySelector("#admin-action-btn"),
};

document.querySelector("#register-btn").addEventListener("click", register);
document.querySelector("#login-btn").addEventListener("click", login);
document.querySelector("#logout-btn").addEventListener("click", logout);
document.querySelector("#verify-btn").addEventListener("click", verifyToken);
document.querySelector("#refresh-profile-btn").addEventListener("click", loadProfile);
els.userActionBtn.addEventListener("click", () => log("User report opened for " + state.claims.sub));
els.adminActionBtn.addEventListener("click", () => log("Admin console opened for " + state.claims.sub));

init();

function init() {
  els.tokenBox.value = state.token;
  if (state.token) {
    verifyToken();
  } else {
    applyAuthorization(null);
  }
}

async function register() {
  const payload = {
    username: els.username.value.trim(),
    password: els.password.value,
    claims: {
      role: els.role.value,
      department: els.department.value.trim(),
    },
  };

  try {
    const result = await api("/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setStatus(`Registered ${result.username}. Log in to receive a token.`, "ok");
    log(result);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function login() {
  try {
    const result = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: els.username.value.trim(),
        password: els.password.value,
      }),
    });

    state.token = result.token;
    state.claims = result.claims;
    localStorage.setItem("roleauth.token", state.token);
    els.tokenBox.value = state.token;
    setStatus("Login successful. Token verified from login response.", "ok");
    await verifyToken();
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function verifyToken() {
  const token = els.tokenBox.value.trim();
  if (!token) {
    logout();
    return;
  }

  try {
    const result = await api("/auth/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    state.token = token;
    state.claims = result.claims;
    localStorage.setItem("roleauth.token", token);
    applyAuthorization(result.claims);
    setStatus("Token is valid. Role-based access updated.", "ok");
    log({ verified: true, claims: result.claims });
    await loadProfile();
  } catch (error) {
    state.claims = null;
    state.profile = null;
    applyAuthorization(null);
    setStatus(error.message, "error");
    log({ verified: false, error: error.message });
  }
}

async function loadProfile() {
  if (!state.token) {
    setStatus("Log in before loading a profile.", "error");
    return;
  }

  try {
    const profile = await api("/auth/me", {
      headers: { Authorization: `Bearer ${state.token}` },
    });
    state.profile = profile;
    renderProfile(profile);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function logout() {
  state.token = "";
  state.claims = null;
  state.profile = null;
  localStorage.removeItem("roleauth.token");
  els.tokenBox.value = "";
  renderProfile(null);
  applyAuthorization(null);
  setStatus("Signed out.", "");
  log("No authorization checks yet.");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }
  return data;
}

function applyAuthorization(claims) {
  const role = claims && claims.role;
  const authenticated = Boolean(claims);
  const canUseUserArea = authenticated && (role === "user" || role === "admin");
  const canUseAdminArea = authenticated && role === "admin";

  els.sessionPill.textContent = authenticated ? `${claims.sub} / ${role || "no role"}` : "Signed out";
  els.sessionPill.classList.toggle("active", authenticated);

  setAccess(els.userCard, els.userState, els.userActionBtn, canUseUserArea, authenticated ? "User area unlocked." : "Sign in to unlock.");
  setAccess(els.adminCard, els.adminState, els.adminActionBtn, canUseAdminArea, canUseAdminArea ? "Admin area unlocked." : "Admin role required.");

  if (claims) {
    renderClaims(claims);
  } else {
    renderProfile(null);
    els.claimsOutput.textContent = "No verified claims yet.";
  }
}

function setAccess(card, stateEl, button, allowed, message) {
  card.classList.toggle("allowed", allowed);
  button.disabled = !allowed;
  stateEl.textContent = message;
  stateEl.className = "access-state " + (allowed ? "ok" : "locked");
}

function renderProfile(profile) {
  if (!profile) {
    els.profileUsername.textContent = "-";
    els.profileRole.textContent = "-";
    els.profileExp.textContent = "-";
    return;
  }

  const claims = profile.token_claims || {};
  els.profileUsername.textContent = profile.username;
  els.profileRole.textContent = claims.role || profile.claims.role || "-";
  els.profileExp.textContent = claims.exp ? new Date(claims.exp * 1000).toLocaleString() : "-";
  renderClaims(claims);
}

function renderClaims(claims) {
  els.claimsOutput.textContent = JSON.stringify(claims, null, 2);
}

function setStatus(message, type) {
  els.status.textContent = message;
  els.status.className = "status" + (type ? ` ${type}` : "");
}

function log(value) {
  els.authLog.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}
