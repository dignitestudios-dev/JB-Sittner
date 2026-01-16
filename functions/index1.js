const { onRequest } = require("firebase-functions/v2/https");
const { setGlobalOptions } = require("firebase-functions/v2");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const logger = require("firebase-functions/logger");
// Set global options for all functions
setGlobalOptions({ maxInstances: 10 });

// Local config
const LOCAL_CONFIG = {
  OTP_TTL_MS: 100 * 365 * 24 * 60 * 60 * 1000,
  SMPT_APP_PASS: "lpmtbpqzwlayghvp",
  SMPT_MAIL: "jbstdispatch@gmail.com",
  SMPT_HOST: "gmail",
  SMPT_PORT: 465,
  OTP_SECRET: "jb-sittner-otp-secret-key",
};

// Example simple function
exports.helloHttp = onRequest((req, res) => {
  logger.info("helloHttp called", { method: req.method, path: req.path });
  res.send("Hello from Firebase HTTP function!");
});

// Helper functions
function generateOTP() {
  return Math.floor(Math.random() * 1000000)
    .toString()
    .padStart(6, "0");
}

function createOtpToken(otp) {
  // Create a token that embeds an expiry and an HMAC signature so it can be
  // verified later without storing state. Format: <expiry>.<hex-hmac>
  const expiry = Date.now() + LOCAL_CONFIG.OTP_TTL_MS;
  const sig = crypto
    .createHmac("sha256", LOCAL_CONFIG.OTP_SECRET)
    .update(`${otp}|${expiry}`)
    .digest("hex");
  return `${expiry}.${sig}`;
}

// Implement sendEmail function
async function sendEmail(to, subject, html) {
  const transporter = nodemailer.createTransport({
    service: LOCAL_CONFIG.SMPT_HOST,
    port: LOCAL_CONFIG.SMPT_PORT,
    secure: LOCAL_CONFIG.SMPT_PORT === 465,
    auth: {
      user: LOCAL_CONFIG.SMPT_MAIL,
      pass: LOCAL_CONFIG.SMPT_APP_PASS,
    },
  });

  const mailOptions = { from: LOCAL_CONFIG.SMPT_MAIL, to, subject, html };
  const result = await transporter.sendMail(mailOptions);
  logger.info(`Email sent to ${to}: ${result.messageId}`);
  return result;
}


// 2nd Gen function using onRequest
exports.sendOTP = onRequest({ region: "us-central1" }, async (req, res) => {
  try {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, POST");
    res.set("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.status(204).send("");
      return;
    }

    const email = req.query.email || (req.body && req.body.email);

    if (!email)
      return res.status(400).json({ success: false, message: "Missing email" });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email))
      return res
        .status(400)
        .json({ success: false, message: "Invalid email format" });

    const otp = generateOTP();
    const html = `<p>Your OTP: <strong>${otp}</strong></p>`;

    await sendEmail(email, "Your OTP", html);
    const token = createOtpToken(otp);

    logger.info(`OTP sent for ${email}: ${otp}, token: ${token}`);
    res.json({ success: true, token, message: "OTP sent successfully" });
  } catch (err) {
    logger.error("sendOTP error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to send OTP",
      error: err.message,
    });
  }
});

// Add a test endpoint to verify email configuration
exports.testEmail = onRequest(async (req, res) => {
  try {
    const testEmail = "test@example.com"; // Change to your test email
    const subject = "Test Email from Firebase Functions";
    const html = `
      <div style="font-family: Arial, sans-serif;">
        <h2>Test Email</h2>
        <p>If you're reading this, your email configuration is working correctly!</p>
        <p>SMTP Configuration:</p>
        <ul>
          <li>Host: ${LOCAL_CONFIG.SMPT_HOST}</li>
          <li>Port: ${LOCAL_CONFIG.SMPT_PORT}</li>
          <li>From: ${LOCAL_CONFIG.SMPT_MAIL}</li>
        </ul>
      </div>
    `;

    await sendEmail(testEmail, subject, html);

    res.json({
      success: true,
      message: "Test email sent successfully",
    });
  } catch (err) {
    console.error("Test email error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to send test email",
      error: err.message,
    });
  }
});

// Verify OTP endpoint (uses LOCAL_CONFIG.OTP_SECRET for local testing)
exports.verifyOTP = onRequest(async (req, res) => {
  try {
    // CORS
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, POST");
    res.set("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.status(204).send("");
      return;
    }

    const token = req.query.token || (req.body && req.body.token);
    const otp = req.query.otp || (req.body && req.body.otp);

    const result = verifyOtpToken(token, otp);
    if (result.valid) {
      return res.json({ success: true, message: "OTP verified" });
    }
    return res.status(400).json({ success: false, message: result.message });
  } catch (err) {
    console.error("verifyOTP error:", err);
    return res.status(500).json({
      success: false,
      message: "Verification failed",
      error: String(err),
    });
  }
});

function verifyOtpToken(token, otp) {
  const secret = LOCAL_CONFIG.OTP_SECRET;
  if (!secret) return { valid: false, message: "OTP secret not configured" };
  if (!token || !otp) return { valid: false, message: "Missing token or otp" };

  const parts = String(token).split(".");
  if (parts.length !== 2)
    return { valid: false, message: "Invalid token format" };
  const expiry = Number(parts[0]);
  const sig = parts[1];
  if (Number.isNaN(expiry))
    return { valid: false, message: "Invalid token expiry" };
  if (Date.now() > expiry) return { valid: false, message: "Token expired" };

  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${otp}|${expiry}`)
    .digest("hex");

  // timing-safe comparison
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(sig, "hex");
  if (a.length !== b.length)
    return { valid: false, message: "Invalid signature" };
  const equal = crypto.timingSafeEqual(a, b);
  return { valid: equal, message: equal ? "OK" : "Invalid otp" };
}
