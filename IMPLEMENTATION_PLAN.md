# Web Route — Implementation Plan

## 1. Product definition

Build a WordPress plugin named **Web Route**. Its default protected login entry point is `/web-route`. The plugin protects privileged WordPress accounts with:

1. username/password verification;
2. approval by a designated administrator through a separate channel;
3. a three-failure IP lock for one hour;
4. decoy pages for direct, logged-out access to WordPress login/admin URLs; and
5. conservative WordPress fingerprint-reduction controls.

The approval feature is an administrator-approval second step, not code-based TOTP/WebAuthn. It can involve a different person, or the same administrator's verified mailbox as the second channel.

### Initial defaults

- Protected login route: `/web-route`
- Protected users: accounts with `manage_options`; on Multisite, network super administrators
- Approvers: explicitly selected administrators; Multisite defaults to selected super administrators
- Approval request lifetime: 10 minutes
- Failed credential threshold: 3 failures per normalized IP
- Failure window: 15 minutes
- Block duration: 60 minutes
- Successful session: normal WordPress session duration, with the submitted “Remember me” preference
- Audit retention: 30 days

The route name is configurable, but changing it requires a fresh preflight check. `web-route` is memorable rather than secret, so the design must not treat the route as an authentication factor.

## 2. Safety boundaries and non-goals

- Do not claim that WordPress can be made undetectable. Public markup, asset paths, hosting headers, REST behavior, and third-party themes/plugins can reveal it.
- The decoy page is a noise-reduction and branding measure, not the main security control.
- Do not block the public website when an IP is rate-limited; block only protected authentication actions.
- Do not blindly block `admin-ajax.php`, `admin-post.php`, REST, cron, CLI, or authenticated admin traffic. These require explicit handling to avoid breaking the site.
- Do not trust `X-Forwarded-For` or similar headers unless the request came through an administrator-configured trusted proxy.
- Do not enable enforcement until an approver, email delivery, HTTPS, recovery access, and route compatibility have all passed setup checks.

## 3. User journeys

### 3.1 Protected login

1. Visitor opens `/web-route` over HTTPS.
2. Rate limiter checks the normalized client IP before password work.
3. Visitor submits username/email, password, and optional “Remember me.”
4. WordPress verifies the credentials through its authentication API, preserving password hashing and account-status checks.
5. The plugin returns the same generic error for an unknown account and a wrong password.
6. A failed credential check increments the IP counter atomically. On failure number 3, the IP is blocked immediately for 60 minutes and sees the blocked page.
7. Valid credentials do **not** create an auth cookie. Instead, the plugin creates a short-lived pending approval request and resets that IP's failed-credential counter.
8. The original browser receives an opaque request handle and a separate high-entropy verifier in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie.
9. The login page changes to a “Waiting for approval” screen and polls a same-route status endpoint with backoff.
10. A designated approver receives an email and can also see the request in an authenticated approval queue.
11. Approval changes only the request status. The approval link never logs in the approver or requester.
12. The original browser presents its request handle and verifier. After a single-use atomic exchange, WordPress sets the requester’s auth cookie and redirects only to a validated same-site admin URL.

### 3.2 Approval and denial

- Notification includes site display name, requesting account display label, normalized IP, browser summary, request time, and expiry.
- Email approval/denial URLs use separate random bearer tokens; store only token hashes.
- A GET request only displays a confirmation screen. A POST with a second, short-lived confirmation value performs the decision, protecting against email security scanners that automatically open links.
- Dashboard decisions require an authenticated designated approver, the appropriate capability, and a WordPress CSRF nonce.
- The first valid approve/deny decision wins through a conditional database update.
- Self-approval is disabled when another approver is configured. For a one-administrator site, verified email possession may be permitted as the second channel and is clearly labeled as such.
- Denied and expired requests receive a generic message in the requesting browser; no sensitive approver details are exposed.

### 3.3 Direct WordPress URL behavior

- Logged-out `GET /wp-admin/`, `/wp-login.php`, `/admin`, `/login`, and `/dashboard` show an aqua, black, and white branded decoy page with HTTP `404`, not a redirect loop.
- The decoy uses a branded “Page not found” heading and large centered “404!” message. It must not contain WordPress asset paths, REST calls, generator tags, or plugin identifiers.
- Logged-in, approved users keep normal `/wp-admin/` access.
- Logout, password reset, password-reset confirmation, re-authentication, and interim-login flows are mapped to actions under `/web-route`; they must be covered by integration tests before the core login page is hidden.
- Public AJAX, cron, CLI, and required integration callbacks are handled through explicit allow rules, not a broad URI bypass.

### 3.4 Blocked visitor

- On the third failed credential submission, and on later `/web-route` requests during the block, respond with HTTP `429` and `Retry-After`.
- Render a self-contained aqua, black, and white animated page showing:
  - the escaped public site name;
  - the visitor's normalized IP address;
  - “You are temporarily blocked by [site name]”;
  - the remaining block time; and
  - a non-sensitive support message.
- Use CSS-only animation, no CDN or third-party resource, a strict Content Security Policy, and `prefers-reduced-motion` support.

## 4. Core architecture

Suggested package structure:

```text
rain-admin-login-security/
├── rain-admin-login-security.php
├── uninstall.php
├── readme.txt
├── includes/
│   ├── class-plugin.php
│   ├── class-activator.php
│   ├── class-request-router.php
│   ├── class-authentication-gate.php
│   ├── class-approval-service.php
│   ├── class-rate-limiter.php
│   ├── class-client-ip-resolver.php
│   ├── class-notification-service.php
│   ├── class-hardening.php
│   ├── class-audit-log.php
│   ├── class-cleanup.php
│   └── class-recovery.php
├── admin/
│   ├── class-settings-page.php
│   ├── class-approval-queue.php
│   └── views/
├── public/
│   ├── class-rain-login-page.php
│   ├── css/rain-login.css
│   └── js/rain-login.js
├── templates/
│   ├── login.php
│   ├── waiting.php
│   ├── approval-confirm.php
│   ├── blocked.php
│   └── decoy-404.php
├── languages/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
└── bin/
    └── wp-cli.php
```

Use one bootstrap class, namespaced PHP classes, dependency injection for the clock/mailer/IP resolver, and no executable code in view files beyond escaped rendering.

## 5. Storage design

Use custom tables because rate-limit increments and approval transitions must be atomic. Create and version them with `dbDelta()`.

### `{$wpdb->prefix}rain_login_requests`

- internal numeric ID
- random public request ID
- protected `user_id` (never store password)
- HMAC of normalized IP
- short-lived raw/masked IP display value, with documented privacy retention
- HMAC of user-agent and a non-sensitive browser summary
- hash of original-browser verifier
- hashes of approve and deny tokens
- requested same-origin redirect path
- remember-me flag
- status: `pending`, `approved`, `denied`, `consumed`, `expired`, `cancelled`
- created, expiry, decision, and consumed timestamps in UTC
- deciding approver ID/method where applicable

Indexes: public ID, status/expiry, user/status, and token lookup columns.

### `{$wpdb->prefix}rain_rate_limits`

- binary HMAC of normalized IP as the primary key
- failed count
- failure-window start
- last failure
- blocked-until UTC timestamp

Use a single atomic upsert/update path so simultaneous failed requests cannot evade the threshold. Normalize IPv4/IPv6 before hashing with a site-specific HMAC secret. Do not use an attacker-supplied forwarding header as the key.

### `{$wpdb->prefix}rain_audit_events`

Store security event type, request ID where applicable, actor/requester IDs where allowed, hashed or masked IP, result, and UTC time. Never log passwords, approval tokens, browser verifiers, cookies, or full request bodies. Add privacy-policy text plus WordPress personal-data exporter/eraser integration for any retained personal data.

## 6. WordPress integration points

- Register the `/web-route` endpoint and query variables; flush rewrite rules only on activation or route change.
- Filter generated login, logout, lost-password, and re-auth URLs so core and plugins point to `/web-route` actions.
- Intercept `wp-login.php` during login initialization and unauthenticated admin routing early enough to render the decoy before WordPress redirects.
- Use `wp_authenticate()` for the primary credential check, then intentionally delay `wp_set_auth_cookie()` until approval exchange.
- Add a late authentication gate that prevents protected users from bypassing approval through another form calling `wp_signon()`. Permit only the plugin's narrowly scoped credential-check context.
- On successful exchange, re-check request status/expiry, user existence, protected capability, account eligibility, browser verifier, and configured binding policy before setting current user/auth cookies and firing the normal successful-login action.
- Validate redirect targets with WordPress safe-redirect APIs and restrict to local admin destinations.
- Exclude WP-CLI and cron from browser routing, but do not exclude authentication APIs automatically.
- For Multisite, define whether requests/tables/settings are site-level or network-level before coding; recommended default is network-level enforcement with base tables and `manage_network_options` configuration.

## 7. Client IP and proxy handling

1. Default source is `REMOTE_ADDR`.
2. Support Cloudflare/load-balancer headers only when `REMOTE_ADDR` matches a configured trusted proxy CIDR.
3. Parse only the documented header for that proxy and select the correct untrusted hop.
4. Validate with `filter_var`, canonicalize IPv6, reject malformed or multiple unexpected values, and fall back safely.
5. Provide a diagnostic screen showing the resolved address and source without exposing it publicly.

Consider an optional secondary per-account throttle to stop distributed attacks, but keep the required one-hour block scoped to IP so an attacker cannot trivially lock a known administrator account for everyone.

## 8. Information-exposure reduction

Safe plugin-level defaults:

- generic login and reset responses to reduce username/email enumeration;
- restrict anonymous REST user-list exposure while preserving authenticated/editor use;
- block common author-ID enumeration redirects and expose only public display names where required;
- remove generator, RSD, Windows Live Writer, and unnecessary discovery links;
- send `noindex, nofollow, noarchive` and no-cache headers on Web Route security pages;
- disable XML-RPC authentication and application passwords for protected roles unless explicitly enabled for a tested integration;
- prevent PHP errors, paths, SQL messages, or stack traces from appearing on public security pages.

Server/deployment recommendations, because a plugin cannot guarantee them:

- disable directory indexes;
- block public access to `readme.html`, `license.txt`, backups, dotfiles, logs, and configuration artifacts;
- minimize `Server`/`X-Powered-By` headers at the web server or edge;
- keep WordPress core, themes, and plugins patched;
- use a WAF/CDN rate limit as an outer layer;
- use least-privilege admin accounts and strong unique passwords.

Do not rewrite every theme/plugin asset URL or remove cache-busting versions as a claimed security feature; that is fragile and does not prevent reliable fingerprinting.

## 9. Admin settings and onboarding

Create a settings area available only to appropriate administrators:

- setup checklist and enforcement status;
- Web Route slug setting and collision test;
- designated approvers and verified notification addresses;
- “Send test approval email” action;
- request expiry, failure window, and retention settings;
- trusted proxy CIDRs/header selection;
- compatibility allow rules with warnings;
- protected roles/capabilities;
- hardening toggles;
- pending request queue and recent audit events;
- diagnostics and recovery instructions.

All mutations require capability checks, sanitized/validated input, CSRF nonces, escaped output, and audit events. Sensitive settings should not be autoloaded when unnecessary.

Enforcement can be switched on only after:

1. HTTPS is active;
2. `/web-route` returns the expected route;
3. at least one eligible approver is selected;
4. a test email is confirmed;
5. a recovery method is acknowledged; and
6. compatibility checks pass for the current permalink/Multisite configuration.

## 10. Recovery and failure modes

- Add `wp rain-security status`, `enable`, `disable`, `unblock <ip>`, `requests list`, and `requests cancel` WP-CLI commands.
- Support a documented `wp-config.php` recovery constant that temporarily restores the core login URL. It must produce an admin notice/audit event and must not contain a URL-borne secret.
- If mail fails, leave the request pending but show a generic delivery problem and recovery guidance; never create a session automatically.
- If all approvers are removed/demoted, automatically refuse enforcement changes and show a critical Site Health test.
- If the custom tables are unavailable, fail closed for protected login but leave WP-CLI recovery functional.
- Deactivation restores normal WordPress routing. Uninstall removes settings/tables only after an explicit “remove data on uninstall” choice.
- Expire stale requests both opportunistically and with WP-Cron so security does not depend on cron running on time.

## 11. Animated page specification

Use a shared, self-contained design system for login, waiting, denied, blocked, and decoy pages:

- white background, blue gradients, soft glass panels, animated rings/particles, and clear focus states;
- responsive down to 320 px and usable at 200% zoom;
- WCAG AA contrast and full keyboard support;
- reduced-motion mode that removes nonessential movement;
- no external fonts, analytics, images, libraries, or identifying WordPress URLs;
- strict output escaping and a restrictive CSP;
- target total CSS/JS payload below 50 KB compressed.

The decoy should be polished but lightweight. The blocked page may show the visitor's own IP as requested; no other visitor/account information may be rendered.

## 12. Implementation phases

### Phase 1 — Foundation and preflight

- Scaffold plugin, namespaces, activation/deactivation, settings, schema versions, and coding standards.
- Implement setup checklist, HTTPS/route/email tests, recovery constant, and basic WP-CLI status/disable commands.
- Add automated WordPress test environment and CI lint/static-analysis jobs.

**Exit:** plugin activates/deactivates cleanly, creates versioned tables, and cannot enable enforcement without passing setup.

### Phase 2 — Route and UI

- Implement `/web-route`, route collision detection, core login URL filters, templates, assets, security headers, and accessible animations.
- Implement action routing for login, logout, lost password, reset confirmation, and re-auth.
- Build decoy interception with explicit AJAX/cron/CLI/compatibility rules.

**Exit:** all core account flows work through `/web-route`; direct logged-out WordPress login/admin URLs return the decoy without loops.

### Phase 3 — Rate limiting

- Implement trusted-proxy-aware IP resolution, normalized/HMAC keys, atomic counters, 15-minute window, and 60-minute blocks.
- Add the 429 block page, countdown, `Retry-After`, manual unblock, cleanup, and audit events.

**Exit:** exactly the third failed credential attempt blocks the IP for one hour under both sequential and concurrent test traffic.

### Phase 4 — Approval gate

- Implement pending requests, original-browser verifier, email/dashboard approve/deny, GET-to-confirm then POST decision, expiry, polling, and single-use exchange.
- Add late authentication guard against alternate `wp_signon()` paths and prevent duplicate notification spam.
- Revalidate the user and capability at exchange before setting the WordPress session.

**Exit:** valid credentials alone never yield an admin session; approval alone never yields a session; only the originating browser can consume a valid approval once.

### Phase 5 — Hardening and privacy

- Add enumeration reduction, discovery-link cleanup, optional XML-RPC/application-password policy, privacy exporter/eraser, retention, and Site Health checks.
- Add deployment guidance for server-level leakage the plugin cannot control.

**Exit:** hardening passes regression tests and does not break normal public REST/content behavior under the selected settings.

### Phase 6 — Compatibility, QA, and release

- Test current supported WordPress/PHP versions, single site, Multisite, subdirectory installs, IPv4/IPv6, reverse proxies, persistent object cache, and common SMTP/security/caching plugins.
- Run PHPCS WordPress standards, PHPStan, unit/integration/end-to-end tests, dependency audit, accessibility scan, and a focused security review.
- Package translation template, `readme.txt`, upgrade/migration logic, admin documentation, recovery runbook, and changelog.

**Exit:** all acceptance criteria pass in a clean install and an upgrade test, with no high/critical security findings.

## 13. Critical test matrix

- Correct/incorrect username, email, password, empty fields, Unicode input, and generic errors.
- Third failure boundary, expiry boundary, concurrent failures, IPv6, proxy spoofing, shared/NAT IP, and block cleanup.
- Approval, denial, expiry, duplicate decisions, replay, token guessing, token leakage prevention, scanner GET, and concurrent exchanges.
- Changed password, deleted/demoted user, removed approver, expired browser cookie, changed user agent/IP, and lost waiting tab.
- Direct `/wp-admin`, `/wp-login.php`, `/admin`, `/login`, query variants, encoded paths, mixed case, subdirectory and Multisite routes.
- Logout, lost password, reset key, forced re-auth, session expiration, and “Remember me.”
- `admin-ajax.php`, cron, WP-CLI, REST, XML-RPC, application passwords, and common front-end login integrations.
- CSRF, XSS, SQL injection, open redirect, email-header injection, cache poisoning, timing/user enumeration, and log/token leakage.
- Mobile layouts, keyboard-only use, screen reader labels, reduced motion, CSP, and no-JavaScript fallback.

## 14. Release acceptance criteria

- `/web-route` is the only normal browser entry point for protected admin login.
- Direct logged-out WordPress admin/login URLs return the branded 404 decoy.
- Three failed credentials from the same resolved IP cause an immediate 60-minute protected-login block and a 429 page showing that visitor's IP and the configured site name.
- A valid password creates no authentication cookie before approval.
- A designated approver can approve or deny, but cannot accidentally log in the requester by opening the link.
- An approved request is short-lived, browser-bound, atomic, and single-use.
- Alternate WordPress sign-on paths cannot bypass approval for protected accounts.
- Emergency recovery works without email or browser access.
- No password, raw token, verifier, auth cookie, or unnecessary full IP is written to logs.
- The plugin clearly documents that fingerprint reduction is partial and complements—rather than replaces—updates, strong authentication, backups, and server/WAF controls.

## 15. Decisions required before implementation

1. Confirm whether “super admin” means Multisite super administrator, a normal single-site administrator, or a specific list of approvers.
2. Confirm email as the approval channel for version 1; SMS/WhatsApp/push would require a provider, credentials, delivery security, and additional privacy work.
3. Decide whether front-end customer/subscriber login exists and must keep using standard/custom login forms.
4. Confirm that the lowercase `/web-route` path is compatible across hosting platforms.
5. Choose the supported WordPress/PHP version range and whether WordPress.org directory compliance is required.
