# 📷 Memory Vault

> **Preserve the photograph. Remember the story.**

Memory Vault is a family photo-and-story archive built for ordinary users in Pakistan, including older and non-technical people. Accounts use a **Pakistani mobile number + password + OTP verification** (no email needed).

> **Status: working foundation.** Accounts, server-side memory storage, privacy rules, family invitations and more are built and covered by automated tests. See [Roadmap](#roadmap) for what is still missing.

## Features

**Authentication (server-side)**
- Sign up with name, Pakistani mobile number (`03XX XXXXXXX` or `+92 3XX XXXXXXX`, stored as `+923XXXXXXXXX`) and password
- 6-digit OTP verification by SMS, or WhatsApp when configured
- Log in, forgot/reset password, change mobile number (verified before it changes)
- Active sessions, "log out of other devices", account deletion with 30-day recovery
- Roles: `owner`, `admin` (admin-only API route is enforced on the server)
- Password strength meter and plain-language error messages

**Archive (saved on the server, tied to your account)**
- 7-step "Preserve a Memory" flow: photo, people, date, location, story (text + voice recording), privacy, preview
- Gallery with 3D / Simple view, search, timeline, family list, sample demo memories
- **Guided story interview**: 6 simple questions (English, Urdu, Sindhi), read aloud, turned into a story
- **Speak to type** (browser speech recognition; Chrome may send audio to Google, and the app asks first)
- **Completeness meter** and a "Needs Help" page that lists missing names, places and stories
- **Edit** any memory later, **backup/restore** to a file, and a **printable Family Book** (print or save as PDF)
- **Server-side storage**: photos and recordings are validated (real file type and size) and saved as files; only owners and permitted people can open them
- **Privacy enforced on the server**: private / family / private link / public, plus roles (owner, family member, viewer)
- **Family**: invite by mobile number, accept/decline, remove or leave, activity history, in-app notifications
- **Ask a relative**: a private link where someone without an account can answer by text or voice; answers wait for your approval
- **Time capsule**: hide a memory from family and link viewers until a date
- **Reports + admin page** (`/admin.html`), change password, profile sync, 30-day account purge, Terms/Privacy templates, installable app (PWA shell)
- Dark/light theme, English / Urdu / Sindhi (main interface), reduced-motion support

## Security

- Passwords hashed with **bcrypt** (cost 12); never stored or returned in plain text
- OTPs: cryptographically random, **stored only as an HMAC hash**, 5-minute expiry, single use, replaced on resend, 5 attempts max, 60-second resend cooldown; never returned by the API
- Login lockout (15 min after 5 wrong passwords) plus IP rate limiting
- Sessions: random token in an `httpOnly`, `SameSite=Strict` cookie (`Secure` in production); only a hash is stored in the database
- CSRF defence: custom `X-Requested-With` header required on all non-GET requests
- Security headers via Helmet; input validation and phone normalization on the server
- Password reset invalidates all sessions
- `mock` SMS provider is **refused when `NODE_ENV=production`**; no fixed/universal OTP exists

## Requirements

- **Node.js 22.13 or newer** (uses the built-in `node:sqlite`, so nothing needs compiling; it prints an "experimental" warning, which is harmless)

## Quick start

```bash
git clone https://github.com/<your-username>/memory-vault.git
cd memory-vault
npm install
cp .env.example .env     # Windows: copy .env.example .env
npm start
```

Open **http://localhost:3000**.

In the default test mode (`AUTH_PROVIDER=mock`) **no real SMS is sent**. The 6-digit code is printed in the server terminal on a line starting with `[DEV ONLY]`.

## Configuration (`.env`)

| Variable | Description |
|---|---|
| `AUTH_PROVIDER` | `mock` (development only) or `twilio` |
| `OTP_SECRET` | Long random string used to hash OTPs and session tokens. **Required in production** |
| `TWILIO_SID`, `TWILIO_TOKEN` | Twilio credentials |
| `TWILIO_FROM` | Sender number for SMS |
| `TWILIO_WHATSAPP_FROM` | Optional. Enables the WhatsApp option |
| `NODE_ENV` | `development` or `production` (production requires HTTPS) |
| `PORT` | Default `3000` |
| `DB_FILE` | SQLite file path, default `vault.db` |
| `UPLOAD_DIR` | Where photos/recordings are stored, default `./uploads` |
| `BASE_URL` | Site address used in invitation messages |
| `ADMIN_PHONES` | Comma-separated numbers that become admins |

Never commit `.env`. It is already in `.gitignore`.

## Project structure

```
server.js            Express API: auth, OTP service, sessions, rate limits
public/index.html    Login, sign-up, OTP, reset, settings screens
public/archive.html  Photo & story archive (localStorage)
.env.example         Configuration template
.vscode/launch.json  Press F5 in VS Code to run
```

OTP delivery goes through a small provider layer (`providers.mock`, `providers.twilio`), so other SMS gateways can be added without touching the auth logic.

## API overview

All `POST` requests need the header `X-Requested-With: memoryvault`.

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/signup` | Create account, send OTP |
| POST | `/api/otp/verify` | Verify code (`signup`, `reset`, `change`) |
| POST | `/api/otp/resend` | Resend code (with cooldown) |
| POST | `/api/login` / `/api/logout` | Log in / out |
| GET | `/api/me` | Current user |
| POST | `/api/reset/start`, `/api/reset/finish` | Forgot password |
| POST | `/api/phone/start` | Start mobile-number change |
| GET/POST | `/api/sessions`, `/api/sessions/others` | List / revoke sessions |
| POST | `/api/account/delete` | Delete account (30-day recovery) |
| GET | `/api/admin/users` | Admin only |

## Tests

```bash
npm test
```

Starts a temporary server and checks privacy, roles, link access, time capsule, uploads, reports and password changes.

## Roadmap

- [ ] Multiple photos per memory and photo cropping
- [ ] Voice transcripts so recordings are searchable
- [ ] Family tree, places map, birthday/anniversary reminders
- [ ] Three.js Memory Universe, audio waveform
- [ ] Separate OTP boxes, profile photo, all pages in Urdu and Sindhi
- [ ] Move files to cloud object storage, add backups and HTTPS hosting
- [ ] Legal review of Terms and Privacy

## Known limitations

- Photos and recordings are stored on the server's disk (`uploads/`); back that folder up along with the database
- The service worker only caches the app shell; memories need a connection
- Sign-up reveals whether a number already has an account (a usability trade-off)
- Terms and Privacy pages are templates, not legal advice
- Not security-audited. Review before handling real family data in production

## License

Add a license before publishing (for example MIT).
