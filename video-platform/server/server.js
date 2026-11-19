require("dotenv").config();

const crypto = require("node:crypto");
const http = require("node:http");
const path = require("node:path");
const cors = require("cors");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const geoip = require("geoip-lite");
const helmet = require("helmet");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const Razorpay = require("razorpay");
const { rateLimit } = require("express-rate-limit");
const { Server: SocketServer } = require("socket.io");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = process.env.MONGODB_URI;
const isProduction = process.env.NODE_ENV === "production";
const demoAuthEnabled = !isProduction && process.env.ALLOW_DEMO_AUTH === "true";
const allowFileOrigin = !isProduction && process.env.ALLOW_FILE_ORIGIN === "true";
const appOrigin = process.env.APP_ORIGIN || `http://localhost:${PORT}`;

const plans = {
  Free: { amount: 0, downloadsPerDay: 1, watchTimeHours: 2, adFree: false, benefits: ["1 download per day", "2 hours daily watch time", "Standard ads"] },
  Bronze: { amount: 4900, downloadsPerDay: 5, watchTimeHours: 6, adFree: false, benefits: ["5 downloads per day", "6 hours daily watch time", "Fewer ads"] },
  Silver: { amount: 9900, downloadsPerDay: 15, watchTimeHours: 12, adFree: true, benefits: ["15 downloads per day", "12 hours daily watch time", "Ad-free viewing"] },
  Gold: { amount: 19900, downloadsPerDay: 30, watchTimeHours: null, adFree: true, benefits: ["30 downloads per day", "Unlimited watch time", "Ad-free + early access"] }
};
const resolveAutoTheme = (date = new Date()) => {
  const hour = Number(new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Kolkata", hour: "2-digit", hourCycle: "h23" }).formatToParts(date).find(part => part.type === "hour").value);
  return hour >= 10 && hour < 12 ? "light" : "dark";
};
const resolveEffectiveTheme = user => user.themePreference === "auto" ? resolveAutoTheme() : user.themePreference;
const deviceFingerprint = (ip, userAgent) => crypto.createHmac("sha256", process.env.DEVICE_HASH_SECRET || process.env.SESSION_SECRET || "local-development-only-change-this-secret").update(`${ip}|${userAgent}`).digest("hex");
const otpHash = code => crypto.createHmac("sha256", process.env.OTP_SECRET || process.env.SESSION_SECRET || "local-development-only-change-this-secret").update(code).digest("hex");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  plan: { type: String, enum: Object.keys(plans), default: "Free" },
  planExpiresAt: { type: Date, default: null },
  themePreference: { type: String, enum: ["auto", "light", "dark"], default: "auto" },
  trustedDevices: [{ fingerprint: String, city: String, state: String, country: String, label: String, lastSeenAt: Date }]
}, { timestamps: true });

const paymentSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  paymentId: { type: String, unique: true, sparse: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "LoopUser", required: true, index: true },
  plan: { type: String, enum: Object.keys(plans), required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true, default: "INR" },
  status: { type: String, enum: ["created", "paid", "failed"], default: "created" },
  receiptEmailSent: { type: Boolean, default: false },
  receiptEmailSentAt: { type: Date, default: null }
}, { timestamps: true });

const User = mongoose.models.LoopUser || mongoose.model("LoopUser", userSchema);
const Payment = mongoose.models.LoopPayment || mongoose.model("LoopPayment", paymentSchema);
const otpSchema = new mongoose.Schema({
  challengeId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "LoopUser", required: true },
  email: { type: String, required: true, lowercase: true },
  codeHash: { type: String, required: true },
  deviceFingerprint: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  country: { type: String, required: true },
  attempts: { type: Number, default: 0 },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });
const OtpChallenge = mongoose.models.LoopOtpChallenge || mongoose.model("LoopOtpChallenge", otpSchema);

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://checkout.razorpay.com"],
  styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
  fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
  imgSrc: ["'self'", "data:", "https://images.unsplash.com"],
  mediaSrc: ["'self'", "blob:", "https://interactive-examples.mdn.mozilla.net"],
  connectSrc: ["'self'", "https://api.razorpay.com", "https://interactive-examples.mdn.mozilla.net"],
  frameSrc: ["'self'", "https://api.razorpay.com", "https://checkout.razorpay.com", "https://*.razorpay.com"],
  objectSrc: ["'none'"],
  upgradeInsecureRequests: null
} } }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || origin === appOrigin || origin === `http://127.0.0.1:${PORT}` || (origin === "null" && allowFileOrigin)) return callback(null, true);
    return callback(new Error("Origin is not allowed"));
  },
  credentials: true
}));
app.use(express.json({ limit: "24kb" }));
app.use(session({
  name: "loop.sid",
  secret: process.env.SESSION_SECRET || "local-development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  store: MONGODB_URI ? MongoStore.create({ mongoUrl: MONGODB_URI, collectionName: "sessions", ttl: 60 * 60 * 24 * 14 }) : undefined,
  cookie: { httpOnly: true, sameSite: "lax", secure: isProduction, maxAge: 1000 * 60 * 60 * 24 * 14 }
}));

const paymentLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: "draft-7", legacyHeaders: false });
const demoLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: "draft-7", legacyHeaders: false });
const requireUser = async (req, res, next) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Sign in to continue." });
    const user = await User.findById(req.session.userId);
    if (!user) return res.status(401).json({ error: "Session user was not found." });
    if (user.planExpiresAt && user.planExpiresAt <= new Date()) {
      user.plan = "Free";
      user.planExpiresAt = null;
      await user.save();
    }
    req.user = user;
    next();
  } catch (error) { next(error); }
};
const getRazorpay = () => {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) throw new Error("Razorpay test credentials are not configured on the server.");
  return new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
};

app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "..", "index.html")));
app.get("/api/config", (_req, res) => res.json({
  razorpayKeyId: process.env.RAZORPAY_KEY_ID || "",
  demoAuthEnabled,
  plans: Object.fromEntries(Object.entries(plans).map(([name, plan]) => [name, { amount: plan.amount, downloadsPerDay: plan.downloadsPerDay, watchTimeHours: plan.watchTimeHours, adFree: plan.adFree, benefits: plan.benefits }]))
}));

async function establishSession(req, user) {
  await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
  req.session.userId = user._id.toString();
  await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
}
async function sendLoginOtp(email, code) {
  const { SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !MAIL_FROM) return false;
  const transporter = nodemailer.createTransport({ host: SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === "true", auth: { user: SMTP_USER, pass: SMTP_PASS } });
  await transporter.sendMail({ from: MAIL_FROM, to: email, subject: "Your LOOP sign-in code", text: `Your LOOP verification code is ${code}. It expires in 10 minutes. If this was not you, secure your account.`, html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#17201b"><h2 style="color:#214c37">Verify your sign-in</h2><p>Enter this code to sign in to LOOP:</p><p style="font-size:28px;letter-spacing:6px;font-weight:bold">${code}</p><p style="color:#758078;font-size:12px">This code expires in 10 minutes. If you did not try to sign in, you can ignore this email.</p></div>` });
  return true;
}

app.post("/api/auth/demo", demoLimiter, async (req, res, next) => {
  if (!demoAuthEnabled) return res.status(404).json({ error: "Demo sign-in is disabled." });
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid receipt email." });
    const user = await User.findOneAndUpdate({ email }, { $setOnInsert: { email, plan: "Free" } }, { new: true, upsert: true, setDefaultsOnInsert: true });
    const userAgent = req.get("user-agent") || "unknown";
    const fingerprint = deviceFingerprint(req.ip, userAgent);
    const location = geoip.lookup(req.ip) || {};
    const city = location.city || "Unknown city";
    const region = location.region || "Unknown state";
    const country = location.country || "Unknown country";
    const trusted = user.trustedDevices.some(device => device.fingerprint === fingerprint && device.city === city && device.state === region && device.country === country);
    if (trusted) {
      const device = user.trustedDevices.find(entry => entry.fingerprint === fingerprint && entry.city === city && entry.state === region && entry.country === country);
      device.lastSeenAt = new Date();
      await user.save();
      await establishSession(req, user);
      return res.json({ authenticated: true, user: { email: user.email, plan: user.plan, themePreference: user.themePreference, effectiveTheme: resolveEffectiveTheme(user) } });
    }
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
    const challengeId = crypto.randomUUID();
    await OtpChallenge.create({ challengeId, userId: user._id, email, codeHash: otpHash(code), deviceFingerprint: fingerprint, city, state: region, country, expiresAt: new Date(Date.now() + 10 * 60 * 1000) });
    let emailSent = false;
    try { emailSent = await sendLoginOtp(email, code); }
    catch (emailError) { await OtpChallenge.deleteOne({ challengeId }); throw emailError; }
    const response = { otpRequired: true, challengeId, emailSent, location: { city, state: region, country }, message: emailSent ? `A verification code was sent to ${email}.` : "Email delivery is not configured." };
    if (!emailSent && !isProduction && process.env.ALLOW_DEMO_OTP_ECHO === "true") response.developmentCode = code;
    if (!emailSent && (isProduction || process.env.ALLOW_DEMO_OTP_ECHO !== "true")) {
      await OtpChallenge.deleteOne({ challengeId });
      return res.status(503).json({ error: "Email verification is unavailable. Configure SMTP and try again." });
    }
    res.status(202).json(response);
  } catch (error) { next(error); }
});

app.post("/api/auth/demo/verify-otp", demoLimiter, async (req, res, next) => {
  if (!demoAuthEnabled) return res.status(404).json({ error: "Demo sign-in is disabled." });
  try {
    const challengeId = String(req.body.challengeId || "");
    const code = String(req.body.code || "").trim();
    const challenge = await OtpChallenge.findOne({ challengeId });
    if (!challenge || challenge.expiresAt <= new Date()) return res.status(400).json({ error: "That verification code expired. Start sign-in again." });
    if (!/^\d{6}$/.test(code) || !safeEqualHex(otpHash(code), challenge.codeHash)) {
      challenge.attempts += 1;
      if (challenge.attempts >= 5) await challenge.deleteOne();
      else await challenge.save();
      return res.status(400).json({ error: challenge.attempts >= 5 ? "Too many incorrect codes. Start sign-in again." : "That code is not correct." });
    }
    const user = await User.findById(challenge.userId);
    if (!user) return res.status(400).json({ error: "Account not found. Start sign-in again." });
    user.trustedDevices.push({ fingerprint: challenge.deviceFingerprint, city: challenge.city, state: challenge.state, country: challenge.country, label: String(req.get("user-agent") || "Device").slice(0, 100), lastSeenAt: new Date() });
    await user.save();
    await challenge.deleteOne();
    await establishSession(req, user);
    res.json({ authenticated: true, user: { email: user.email, plan: user.plan, themePreference: user.themePreference, effectiveTheme: resolveEffectiveTheme(user) } });
  } catch (error) { next(error); }
});

app.get("/api/me", requireUser, (req, res) => res.json({ user: { email: req.user.email, plan: req.user.plan, planExpiresAt: req.user.planExpiresAt, themePreference: req.user.themePreference, effectiveTheme: resolveEffectiveTheme(req.user), trustedDevices: req.user.trustedDevices.map(device => ({ city: device.city, state: device.state, country: device.country, label: device.label, lastSeenAt: device.lastSeenAt })) }, plans }));
app.patch("/api/me/preferences", requireUser, async (req, res, next) => {
  try {
    const themePreference = req.body.themePreference;
    if (!["auto", "light", "dark"].includes(themePreference)) return res.status(400).json({ error: "Theme must be auto, light, or dark." });
    req.user.themePreference = themePreference;
    await req.user.save();
    res.json({ themePreference, effectiveTheme: resolveEffectiveTheme(req.user) });
  } catch (error) { next(error); }
});

app.post("/api/payments/order", paymentLimiter, requireUser, async (req, res, next) => {
  try {
    const plan = plans[req.body.plan];
    if (!plan || req.body.plan === "Free") return res.status(400).json({ error: "Choose a paid plan." });
    const client = getRazorpay();
    const order = await client.orders.create({
      amount: plan.amount,
      currency: "INR",
      receipt: `loop_${req.user._id}_${Date.now()}`,
      notes: { userId: req.user._id.toString(), plan: req.body.plan }
    });
    await Payment.create({ orderId: order.id, userId: req.user._id, plan: req.body.plan, amount: plan.amount, currency: "INR" });
    res.status(201).json({ id: order.id, amount: order.amount, currency: order.currency, plan: req.body.plan });
  } catch (error) { next(error); }
});

const safeEqualHex = (first, second) => {
  if (typeof first !== "string" || typeof second !== "string" || !/^[\da-f]{64}$/i.test(first) || !/^[\da-f]{64}$/i.test(second)) return false;
  return crypto.timingSafeEqual(Buffer.from(first, "hex"), Buffer.from(second, "hex"));
};
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

async function sendPaymentReceipt(user, payment) {
  const { SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !MAIL_FROM) return false;
  const transporter = nodemailer.createTransport({ host: SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === "true", auth: { user: SMTP_USER, pass: SMTP_PASS } });
  const plan = plans[payment.plan];
  const amount = new Intl.NumberFormat("en-IN", { style: "currency", currency: payment.currency }).format(payment.amount / 100);
  await transporter.sendMail({
    from: MAIL_FROM,
    to: user.email,
    subject: `LOOP ${payment.plan} plan payment confirmed`,
    text: `Your LOOP ${payment.plan} plan is active for 30 days. Amount: ${amount}. Order: ${payment.orderId}. Payment: ${payment.paymentId}. Downloads per day: ${plan.downloadsPerDay}.`,
    html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#17201b"><h1 style="color:#214c37">LOOP payment confirmed</h1><p>Your <strong>${escapeHtml(payment.plan)}</strong> plan is active for 30 days.</p><table style="width:100%;border-collapse:collapse"><tr><td style="padding:8px;border-bottom:1px solid #e4e9e3">Amount paid</td><td style="padding:8px;border-bottom:1px solid #e4e9e3">${escapeHtml(amount)}</td></tr><tr><td style="padding:8px;border-bottom:1px solid #e4e9e3">Downloads per day</td><td style="padding:8px;border-bottom:1px solid #e4e9e3">${plan.downloadsPerDay}</td></tr><tr><td style="padding:8px;border-bottom:1px solid #e4e9e3">Order ID</td><td style="padding:8px;border-bottom:1px solid #e4e9e3">${escapeHtml(payment.orderId)}</td></tr><tr><td style="padding:8px;border-bottom:1px solid #e4e9e3">Payment ID</td><td style="padding:8px;border-bottom:1px solid #e4e9e3">${escapeHtml(payment.paymentId)}</td></tr><tr><td style="padding:8px">Transaction date</td><td style="padding:8px">${new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })}</td></tr></table><p style="color:#758078;font-size:12px">This email confirms your LOOP plan upgrade. Keep it for your records.</p></div>`
  });
  return true;
}

app.post("/api/payments/verify", paymentLimiter, requireUser, async (req, res, next) => {
  try {
    const { orderId, paymentId, signature } = req.body;
    if (![orderId, paymentId, signature].every(value => typeof value === "string" && value.length < 256)) return res.status(400).json({ error: "Invalid payment verification details." });
    const record = await Payment.findOne({ orderId, userId: req.user._id });
    if (!record) return res.status(404).json({ error: "Payment order not found for this account." });
    const expected = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || "").update(`${orderId}|${paymentId}`).digest("hex");
    if (!safeEqualHex(expected, signature)) return res.status(400).json({ error: "Payment signature is invalid." });
    if (record.status === "paid") return res.json({ user: { email: req.user.email, plan: req.user.plan }, receiptEmailSent: record.receiptEmailSent });
    const client = getRazorpay();
    const captured = await client.payments.fetch(paymentId);
    if (captured.order_id !== orderId || captured.status !== "captured" || captured.amount !== record.amount || captured.currency !== record.currency) return res.status(400).json({ error: "Payment is not captured for this order." });

    const mongoSession = await mongoose.startSession();
    let paidRecord;
    let updatedUser;
    try {
      await mongoSession.withTransaction(async () => {
        paidRecord = await Payment.findOneAndUpdate({ orderId, userId: req.user._id, status: "created" }, { $set: { paymentId, status: "paid" } }, { new: true, session: mongoSession });
        if (!paidRecord) throw new Error("Payment order has already been processed.");
        const planExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        updatedUser = await User.findByIdAndUpdate(req.user._id, { $set: { plan: record.plan, planExpiresAt } }, { new: true, session: mongoSession });
      });
    } finally { await mongoSession.endSession(); }

    let receiptEmailSent = false;
    try {
      receiptEmailSent = await sendPaymentReceipt(updatedUser, paidRecord);
      if (receiptEmailSent) {
        paidRecord.receiptEmailSent = true;
        paidRecord.receiptEmailSentAt = new Date();
        await paidRecord.save();
      }
    } catch (emailError) { console.error("LOOP receipt email failed:", emailError.message); }
    req.session.userId = updatedUser._id.toString();
    res.json({ user: { email: updatedUser.email, plan: updatedUser.plan, planExpiresAt: updatedUser.planExpiresAt }, receiptEmailSent });
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(error.status || 500).json({ error: error.status && error.status < 500 ? error.message : "Server error. Check server configuration and logs." });
});

const httpServer = http.createServer(app);
const io = new SocketServer(httpServer, {
  cors: {
    origin(origin, callback) {
      if (!origin || origin === appOrigin || origin === `http://127.0.0.1:${PORT}` || (origin === "null" && allowFileOrigin)) return callback(null, true);
      return callback(new Error("Origin is not allowed"));
    },
    credentials: true
  },
  maxHttpBufferSize: 100_000
});
const watchParties = new Map();
const chatRate = new Map();
const cleanPartyName = value => String(value || "Guest").replace(/[<>\u0000-\u001f]/g, "").trim().slice(0, 32) || "Guest";
const partyMembers = room => Array.from(room.participants.values()).map(({ id, name, role }) => ({ id, name, role }));

function removePartyParticipant(socket) {
  const roomId = socket.data.partyId;
  if (!roomId) return;
  const room = watchParties.get(roomId);
  socket.data.partyId = null;
  if (!room) return;
  room.participants.delete(socket.id);
  socket.leave(roomId);
  if (room.hostId === socket.id) {
    io.to(roomId).emit("party:ended", { reason: "The host ended the watch party." });
    watchParties.delete(roomId);
    io.in(roomId).socketsLeave(roomId);
    return;
  }
  io.to(roomId).emit("party:participants", partyMembers(room));
  io.to(roomId).emit("party:participant-left", { id: socket.id });
  if (room.participants.size === 0) watchParties.delete(roomId);
}

io.on("connection", socket => {
  socket.on("party:create", (payload, acknowledge = () => {}) => {
    const videoId = String(payload?.videoId || "").slice(0, 80);
    if (!videoId) return acknowledge({ error: "Choose a video before starting a party." });
    removePartyParticipant(socket);
    const roomId = crypto.randomBytes(10).toString("hex").toUpperCase();
    const participant = { id: socket.id, name: cleanPartyName(payload?.name), role: "host" };
    const room = { id: roomId, hostId: socket.id, videoId, currentTime: Math.max(0, Number(payload?.currentTime) || 0), paused: payload?.paused !== false, participants: new Map([[socket.id, participant]]) };
    watchParties.set(roomId, room);
    socket.data.partyId = roomId;
    socket.join(roomId);
    acknowledge({ roomId, selfId: socket.id, hostId: socket.id, videoId: room.videoId, currentTime: room.currentTime, paused: room.paused, participants: partyMembers(room) });
  });

  socket.on("party:join", (payload, acknowledge = () => {}) => {
    const roomId = String(payload?.roomId || "").toUpperCase().replace(/[^A-F0-9]/g, "").slice(0, 20);
    const room = watchParties.get(roomId);
    if (!room) return acknowledge({ error: "This watch party is not available." });
    if (room.participants.size >= 8) return acknowledge({ error: "This watch party is full (8 participants maximum)." });
    removePartyParticipant(socket);
    const participant = { id: socket.id, name: cleanPartyName(payload?.name), role: "guest" };
    room.participants.set(socket.id, participant);
    socket.data.partyId = roomId;
    socket.join(roomId);
    acknowledge({ roomId, selfId: socket.id, hostId: room.hostId, videoId: room.videoId, currentTime: room.currentTime, paused: room.paused, participants: partyMembers(room) });
    socket.to(roomId).emit("party:participant-joined", participant);
    io.to(roomId).emit("party:participants", partyMembers(room));
  });

  socket.on("party:sync", payload => {
    const room = watchParties.get(socket.data.partyId);
    if (!room || room.hostId !== socket.id) return;
    const now = Date.now();
    if (now - (socket.data.lastSyncAt || 0) < 250) return;
    socket.data.lastSyncAt = now;
    if (typeof payload?.videoId === "string" && payload.videoId.length <= 80) room.videoId = payload.videoId;
    room.currentTime = Math.max(0, Math.min(86_400, Number(payload?.currentTime) || 0));
    room.paused = Boolean(payload?.paused);
    socket.to(room.id).emit("party:sync", { videoId: room.videoId, currentTime: room.currentTime, paused: room.paused, updatedAt: now });
  });

  socket.on("party:signal", payload => {
    const room = watchParties.get(socket.data.partyId);
    const targetId = String(payload?.targetId || "");
    if (!room || !room.participants.has(targetId) || !payload?.signal || typeof payload.signal !== "object") return;
    socket.to(targetId).emit("party:signal", { fromId: socket.id, signal: payload.signal });
  });

  socket.on("party:chat", payload => {
    const room = watchParties.get(socket.data.partyId);
    const participant = room?.participants.get(socket.id);
    const text = String(payload?.text || "").trim().slice(0, 500);
    if (!room || !participant || !text) return;
    const times = (chatRate.get(socket.id) || []).filter(time => Date.now() - time < 5000);
    if (times.length >= 8) return;
    times.push(Date.now());
    chatRate.set(socket.id, times);
    io.to(room.id).emit("party:chat", { id: crypto.randomUUID(), name: participant.name, text, sentAt: Date.now() });
  });

  socket.on("party:leave", () => removePartyParticipant(socket));
  socket.on("disconnect", () => { removePartyParticipant(socket); chatRate.delete(socket.id); });
});

async function start() {
  if (!MONGODB_URI && isProduction) throw new Error("Set MONGODB_URI in server/.env before starting LOOP in production.");
  if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) throw new Error("Set a strong SESSION_SECRET of at least 32 characters in production.");
  if (MONGODB_URI) await mongoose.connect(MONGODB_URI);
  else console.warn("MongoDB is not configured; account, payment, and login features are unavailable. Watch parties are still enabled.");
  httpServer.listen(PORT, () => console.log(`LOOP is running at http://localhost:${PORT}`));
}

if (require.main === module) start().catch(error => { console.error(error.message); process.exit(1); });
module.exports = { app, httpServer, io, plans, safeEqualHex, resolveAutoTheme };
