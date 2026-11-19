# LOOP subscriptions API

This API supports Razorpay test-mode upgrades, MongoDB plan/payment records, SMTP receipts, and ephemeral Socket.IO watch parties. The app served at `/` is the LOOP frontend.

## Local setup

1. Install Node.js 24+ and use MongoDB Atlas, or run local MongoDB as a replica set (payment updates use a transaction). Watch parties can run without MongoDB in development.
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, a long random `SESSION_SECRET`, Razorpay test keys, and SMTP settings.
3. Run `npm install`, then `npm start` from this folder.
4. Open `http://localhost:3000` and choose **Sign in**. A new device or GeoIP city/state receives a short-lived email OTP. In local development only, `ALLOW_DEMO_OTP_ECHO=true` displays the code in the dialog when SMTP is not configured.
5. In Razorpay test mode, use Razorpay's published test payment details. The server verifies the order signature and confirms the captured payment with Razorpay before updating MongoDB.

Bronze costs INR 49/month, Silver INR 99/month, and Gold INR 199/month in the demo catalog. Payment is a one-time test checkout that grants 30 days; recurring billing is not enabled. Plan expiry is checked when the user next requests `/api/me` or a protected route.

## Email receipts

Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, and `MAIL_FROM`. A receipt contains the selected plan, amount, order ID, payment ID, transaction date, and download allowance. A successful payment still activates the plan if SMTP is temporarily unavailable; the API reports whether a receipt was sent.

## Login security and theme

`/api/auth/demo` is development-only. It uses GeoIP lookup plus a keyed hash of the request IP and user agent to recognize a trusted device. A new device or city/state requires a six-digit email OTP that expires in ten minutes and locks after five failed attempts. Set `DEVICE_HASH_SECRET` and `OTP_SECRET` to independent random secrets. Local/private IP addresses have no GeoIP region, but a new IP/device still triggers verification. The user profile stores `themePreference` (`auto`, `light`, or `dark`); `auto` resolves using Asia/Kolkata time, choosing light from 10:00 to 11:59 AM IST and dark otherwise.

## Watch parties

Watch party rooms use Socket.IO and are held in server memory; they end when the host leaves or the server restarts. The host controls synchronized playback. Guests can join with the host's invite link, exchange chat messages, and connect over peer-to-peer WebRTC. Camera/microphone permissions are optional for playback and chat. Screen sharing and local host-only recording require browser support and user permission. Use HTTPS (localhost is allowed) and configure a TURN relay for reliable calls across restrictive networks. Recordings are created in the host's browser and downloaded locally; they are not uploaded or stored by the server.

## Production requirements

- Set `NODE_ENV=production`, `ALLOW_DEMO_AUTH=false`, `ALLOW_FILE_ORIGIN=false`, a production `APP_ORIGIN`, HTTPS, and a strong session secret.
- Replace `/api/auth/demo` with your real authentication flow. Demo sign-in is development-only and deliberately disabled in production.
- Configure trusted proxy IP handling and a maintained GeoIP database/service for accurate city/state detection. Device/IP changes still trigger OTP when GeoIP is unavailable. Only email OTP is implemented; add a verified SMS provider if mobile OTP is required.
- Keep `RAZORPAY_KEY_SECRET`, MongoDB credentials, session secrets, and SMTP credentials on the server. Never commit `.env` or send secrets in chat.
- Enforce video access and download quotas in authenticated server routes and serve media through protected storage. The current HTML preview uses sample media; its browser-side video lock is for demonstration, not production authorization.
- Configure a Razorpay webhook and reconciliation job before real payments. This scaffold verifies Checkout responses and captured payment state but does not implement webhook recovery or automatic recurring charges.
