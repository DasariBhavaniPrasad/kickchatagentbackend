
const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Temporary storage for testing.
// This will be replaced with per-user database storage
// when we implement multiple users.
let kickAccessToken = null;
let kickRefreshToken = null;

const pendingLogins = new Map();

function credentialsConfigured() {
  return Boolean(
    process.env.KICK_CLIENT_ID &&
    process.env.KICK_CLIENT_SECRET &&
    process.env.KICK_REDIRECT_URI &&
    process.env.MOBILE_REDIRECT_URI
  );
}

// Health check
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "Kick Chat Agent Mobile Backend"
  });
});

// Start official Kick login
app.get("/auth/kick", (req, res) => {
  if (!credentialsConfigured()) {
    return res.status(500).send(
      "Kick OAuth environment variables are missing."
    );
  }

  const state = crypto.randomBytes(32).toString("hex");
  const verifier = crypto.randomBytes(32).toString("base64url");

  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  pendingLogins.set(state, {
    verifier,
    createdAt: Date.now()
  });

  const params = new URLSearchParams({
    client_id: process.env.KICK_CLIENT_ID,
    response_type: "code",
    redirect_uri: process.env.KICK_REDIRECT_URI,
    scope: "user:read channel:read chat:write",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  const authorizationUrl =
    `https://id.kick.com/oauth/authorize?${params.toString()}`;

  res.redirect(authorizationUrl);
});

// Kick OAuth callback
app.get("/auth/kick/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(
      `${process.env.MOBILE_REDIRECT_URI}?status=error`
    );
  }

  const login = pendingLogins.get(state);

  if (!code || !login) {
    return res.status(400).send(
      "Invalid or expired login session."
    );
  }

  pendingLogins.delete(state);

  if (Date.now() - login.createdAt > 10 * 60 * 1000) {
    return res.status(400).send("Login session expired.");
  }

  try {
    const tokenParams = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: process.env.KICK_CLIENT_ID,
      client_secret: process.env.KICK_CLIENT_SECRET,
      redirect_uri: process.env.KICK_REDIRECT_URI,
      code: String(code),
      code_verifier: login.verifier
    });

    const response = await fetch(
      "https://id.kick.com/oauth/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json"
        },
        body: tokenParams
      }
    );

    const data = await response.json();

    if (!response.ok || !data.access_token) {
      console.error("Kick token exchange failed:", response.status);

      return res.redirect(
        `${process.env.MOBILE_REDIRECT_URI}?status=error`
      );
    }

    kickAccessToken = data.access_token;
    kickRefreshToken = data.refresh_token || null;

    console.log("Mobile Kick login successful.");

    return res.redirect(
      `${process.env.MOBILE_REDIRECT_URI}?status=success`
    );

  } catch (err) {
    console.error("OAuth callback error:", err.message);

    return res.redirect(
      `${process.env.MOBILE_REDIRECT_URI}?status=error`
    );
  }
});

// Check connection status
app.get("/api/auth/status", (req, res) => {
  res.json({
    connected: Boolean(kickAccessToken)
  });
});

// Disconnect Kick account
app.post("/api/auth/logout", (req, res) => {
  kickAccessToken = null;
  kickRefreshToken = null;

  res.json({
    success: true,
    connected: false
  });
});

// Start server
app.listen(PORT, () => {
  console.log("--------------------------------");
  console.log("Kick Chat Agent Mobile Backend");
  console.log("Port:", PORT);
  console.log("Kick Client ID configured:",
    Boolean(process.env.KICK_CLIENT_ID));
  console.log("--------------------------------");
});
