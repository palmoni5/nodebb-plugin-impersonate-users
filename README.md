# nodebb-plugin-impersonate-users

A NodeBB plugin that lets administrators and authorized staff sign in as any other user directly from that user's profile menu, without needing their password.

## Features

- **Sign in as another user** — a "Sign in as this user" option appears in the gear dropdown on any user's profile page.
- **One-click return** — while impersonating, a "Return to the original user" option appears on every profile page so you can switch back instantly.
- **Privilege-based access** — works for administrators automatically; other staff can be granted access through the global privilege `impersonate:users` in the ACP.
- **Session isolation** — uses NodeBB's native session handling; the original session is restored cleanly when you return.

## Installation

1. Copy or symlink the plugin directory into your NodeBB `node_modules/` folder, **or** install it via npm once published:
   ```bash
   npm install nodebb-plugin-impersonate-users
   ```
2. Activate the plugin in **ACP → Extend → Plugins**.
3. Restart NodeBB.

## Granting access to non-admin users

1. Go to **ACP → Users → Privileges → Global Privileges**.
2. Find the group or user you want to authorize.
3. Enable the **"Impersonate other users"** privilege.
4. The gear dropdown on profile pages will now show the impersonate option for those users.

## How it works

### Signing in as another user

Navigate to any user's profile page. If you have the impersonate privilege, the gear icon dropdown (top-right of the profile header) will contain a **"Sign in as this user"** option. Clicking it:

1. Revokes your current session.
2. Creates a new session for the target user via NodeBB's native `doLogin`.
3. Stores your original UID in `req.session.impersonatorUid` so you can be restored later.
4. Redirects you to the target user's profile.

### Returning to your original account

While impersonating, every profile page's gear dropdown shows **"Return to the original user"**. Clicking it:

1. Revokes the impersonated session.
2. Restores your original session.
3. Redirects you to your own profile.

## API routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/plugins/impersonate-users/privileges` | Returns the current session state (`canImpersonate`, `isImpersonating`, etc.) |
| `POST` | `/api/plugins/impersonate-users/switch` | Switches to the given `targetUid` |
| `POST` | `/api/plugins/impersonate-users/restore` | Restores the original user |

Page routes (used for direct navigation):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/plugins/impersonate-users/switch/:uid` | Switches to `:uid` and redirects |
| `GET` | `/plugins/impersonate-users/restore` | Restores original user and redirects |

## Languages

| Code | Language |
|------|----------|
| `en-GB` | English |
| `he` | Hebrew |

To add a new language, create a file at `public/languages/<code>/impersonate-users.json` with the following keys:

```json
{
  "admin.impersonate-users": "...",
  "profile.login-as": "...",
  "profile.restore-original": "..."
}
```

## Requirements

- NodeBB 3.x or later
- Node.js 18 or later

## License

GPL-3.0
