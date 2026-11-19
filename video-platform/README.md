# LOOP Video Platform

A responsive video-sharing internship project built around one YouTube-inspired platform. Tasks 1–6 are integrated into this project.

## Run locally

Requirements: Node.js 24+.

```powershell
cd server
Copy-Item .env.example .env
npm install
npm start
```

Open `http://localhost:3000`.

Watch parties can run in development without MongoDB. User accounts, trusted-device verification, theme preferences, subscription payments, and receipts require MongoDB and the relevant private credentials configured in `server/.env`. See [server setup](server/README.md).

## Internship features

- Multilingual comment composer, translation option, basic moderation, likes/dislikes, optional broad-area location, and report-for-review.
- Daily download limits and profile download history.
- Free, Bronze, Silver, and Gold plan cards with Razorpay test checkout integration.
- IST-based Auto theme with saved manual theme preferences and new-device email OTP.
- Custom video playback controls and mobile double-tap seeking.
- Watch parties with invite links, synchronized host playback, live chat, participant list, optional peer-to-peer call and screen share, plus host-only local recording.

## Before submission

- Configure a MongoDB replica set/Atlas, SMTP, Razorpay test keys, and strong secrets in `server/.env` to demonstrate account, OTP, and payment flows. Never publish `.env`.
- Deploy this `video-platform` project publicly to Netlify or Vercel and verify the link in a private browser window. The development server URL is not a public submission URL.
- Watch party rooms are held in server memory and end when the host leaves or the server restarts. Party messages are saved in each participant's browser `localStorage` (up to 300 per room), but are not shared across devices or backed up to MongoDB.
- Comments, reactions, and preview download history are stored in browser `localStorage`; they are not shared across browsers or devices.
- The video catalog uses sample preview media. Upload metadata is a browser demo, not durable video storage.
- Record and review the required 2–5 minute MP4, WebM, or MOV demo before the one-time submission.
