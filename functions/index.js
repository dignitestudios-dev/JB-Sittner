const { onRequest } = require("firebase-functions/v2/https");
const { setGlobalOptions } = require("firebase-functions/v2");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const logger = require("firebase-functions/logger");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const admin = require("firebase-admin");
const twilio = require("twilio");
const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER } = require("./constants");

if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();
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

// Twilio configs
const LOCAL_CONFIG_TWILIO = {
  OTP_TTL_MS: 100 * 365 * 24 * 60 * 60 * 1000,
  SMPT_APP_PASS: "lpmtbpqzwlayghvp",
  SMPT_MAIL: "jbstdispatch@gmail.com",
  SMPT_HOST: "gmail",
  SMPT_PORT: 465,
  OTP_SECRET: "jb-sittner-otp-secret-key",
  // Dummy Twilio config for local testing — replace with real secrets in production
  TWILIO_ACCOUNT_SID: TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN: TWILIO_AUTH_TOKEN,
  TWILIO_FROM_NUMBER: TWILIO_FROM_NUMBER,
};

// Send Sms Phone number using Twilio
async function sendSms(to, message) {
  try {
    if (!to) throw new Error("Missing 'to' phone number");
    if (!message) throw new Error("Missing 'message' parameter");

    // 1️⃣ Convert to string & remove everything except digits
    let digits = String(to).replace(/\D/g, "");

    /**
     * 2️⃣ Normalize to US/Canada E.164
     *
     * Valid inputs:
     *  - 7807776451        → +17807776451
     *  - 17807776451      → +17807776451
     *  - +17807776451     → +17807776451
     *  - (780) 777-6451   → +17807776451
     */

    if (digits.length === 10) {
      // Missing country code → assume US
      digits = "1" + digits;
    }

    if (digits.length !== 11 || !digits.startsWith("1")) {
      throw new Error(`Invalid US phone number: ${to}`);
    }

    const normalizedPhone = `+${digits}`;

    // 3️⃣ Twilio config check
    const sid = LOCAL_CONFIG_TWILIO.TWILIO_ACCOUNT_SID;
    const token = LOCAL_CONFIG_TWILIO.TWILIO_AUTH_TOKEN;
    const from = LOCAL_CONFIG_TWILIO.TWILIO_FROM_NUMBER;

    if (!sid || !token || !from) {
      throw new Error("Twilio not configured properly");
    }

    // 4️⃣ Send SMS
    const client = twilio(sid, token);
    const sent = await client.messages.create({
      body: message,
      from,
      to: normalizedPhone,
    });

    logger.info(`✅ SMS sent to ${normalizedPhone} | SID: ${sent.sid}`);
    return sent;
  } catch (err) {
    logger.error(`❌ sendSms failed for "${to}":`, err.message);
    throw err;
  }
}

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

exports.sendTestSMS = onRequest(async (req, res) => {
  try {
    const testNumber = "14316312066";
    const message = "This is a TEST SMS sent from Firebase Function.";

    await sendSms(testNumber, message);

    logger.info(`📱 Test SMS sent to ${testNumber}`);

    return res.status(200).send({
      success: true,
      message: "Test SMS sent successfully!",
      to: testNumber,
    });
  } catch (error) {
    logger.error("❌ Error sending test SMS:", error);
    return res.status(500).send({
      success: false,
      error: error.message,
    });
  }
});


// new

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

exports.sendUnreadMessageReminders = onSchedule(
  {
    schedule: "* * * * *", // ⏰ every hour at minute 0
    timeZone: "America/Chicago", // US Central Time
    region: "us-central1",
  },
  // eslint-disable-next-line no-unused-vars
  async () => {
    try {
      logger.info("📦 Fetching reminder settings from Firestore...");
      const settingsRef = db.collection("settings").doc("reminder");
      const settingsSnap = await settingsRef.get();

      if (!settingsSnap.exists) {
        logger.warn(
          "⚠️ Reminder settings document not found (settings/reminder). Exiting..."
        );
        return null;
      }

      const reminderData = settingsSnap.data();
      const reminderDays = reminderData.days || 0;
      const reminderHours = reminderData.hours || 0;

      // Convert to milliseconds
      const cutoffMs =
        reminderDays * 24 * 60 * 60 * 1000 + reminderHours * 60 * 60 * 1000;

      const now = new Date();
      const cutoffDate = new Date(now - cutoffMs);

      logger.info(
        `🕒 Reminder threshold set to ${reminderDays} days (${cutoffMs} ms). Cutoff date: ${cutoffDate.toISOString()}`
      );

      // ✅ Get the oldest message older than cutoffDate (limit 1)
      logger.info("📨 Fetching oldest message older than cutoff date...");
      const oldMessageSnap = await db
        .collection("message")
        .where("createdAt", "<", cutoffDate)
        .orderBy("createdAt", "asc")
        .limit(1)
        .get();

      if (oldMessageSnap.empty) {
        logger.info(
          "✅ No messages older than threshold found — skipping reminders."
        );
        return null;
      }

      const oldMessageDoc = oldMessageSnap.docs[0];
      const oldMessage = oldMessageDoc.data();
      logger.info(
        `📄 Oldest message for reminder found: ID=${oldMessageDoc.id}, createdAt=${oldMessage.createdAt}`
      );

      if(oldMessage.isReminder){
        logger.info(
        `📄 Already sent remainder for the last message`
      );
        // return null;
      }

      // 2️⃣ Process employees in batches
      logger.info("👥 Starting to fetch and process employees in batches...");
      const employeesRef = db.collection("employee");
      const batchSize = 50;
      let lastDoc = null;
      let totalProcessed = 0;
      let countReminded = 0;
      let batchCount = 0;

      // eslint-disable-next-line no-constant-condition
      while (true) {
        batchCount++;

        let query = employeesRef.limit(batchSize);
        if (lastDoc) query = query.startAfter(lastDoc);

        const snapshot = await query.get();
        if (snapshot.empty) {
          logger.info(
            "🚫 No more employee documents found. Exiting batch loop."
          );
          break;
        }

        logger.info(
          `📄 Processing ${snapshot.size} employees in batch #${batchCount}...`
        );

        for (const doc of snapshot.docs) {
          totalProcessed++;
          const emp = doc.data();
          const empId = emp.employeeId || "UNKNOWN_ID";
          const empPhone = emp.contact || null;

          const empName = emp.name || "Employee";

          const seenArray = oldMessage.UserMsgSeen || [];
          const hasSeen = seenArray.some((s) => s.employeeId === empId);

          if (!hasSeen) {
            logger.info(
              `🔔 Employee ${empName} (${empId}) has UNREAD messages. Sending reminder...`
            );

            const message = `Hello ${empName}, you have an unread message pending for more than ${reminderDays} days. Please check your message portal at https://dispatch.jbsittnertruckingllc.com/ – JBST Dispatch Team`;

            try {
              await sendSms(empPhone, message);
              countReminded++;
              logger.info(`📱 Reminder SMS sent to ${empPhone}`);
            } catch (e) {
              logger.error(`❌ Failed to send SMS to ${empPhone}`, e);
            }
          }
        }

        lastDoc = snapshot.docs[snapshot.docs.length - 1];
        logger.info(
          `🧾 Finished batch #${batchCount}: processed ${snapshot.size} employees.`
        );
        if (snapshot.size < batchSize) {
          logger.info("🏁 Last batch processed — no more employees left.");
          break;
        }
      }

      // ✅ Update the message document to mark it as reminded
      if (oldMessageDoc && countReminded > 0) {
        try {
          await db.collection("message").doc(oldMessageDoc.id).update({
            isReminder: true,
          });
          logger.info(
            `✅ Updated message ${oldMessageDoc.id} with isReminder: true`
          );
          logger.info(
            `📊 Reminded ${countReminded} employees about this message`
          );
        } catch (updateError) {
          logger.error(
            `❌ Failed to update message ${oldMessageDoc.id}:`,
            updateError
          );
        }
      } else if (countReminded === 0) {
        logger.info(
          "ℹ️ No employees needed reminders - message update skipped"
        );
      }

      logger.info(`🎯 Completed: ${totalProcessed} employees processed.`);
      logger.info(
        `📱 Reminder SMS messages sent to ${countReminded} employees.`
      );
      logger.info(
        "✅ [sendUnreadMessageReminders] Function completed successfully."
      );
      return null;
    } catch (err) {
      logger.error("💥 sendUnreadMessageReminders encountered an error:", err);
      return null;
    }
  }
);
