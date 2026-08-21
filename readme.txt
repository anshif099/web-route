=== web-route ===
Contributors: rainhopes
Requires at least: 6.4
Requires PHP: 7.4
Stable tag: 0.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Web Route protects privileged WordPress browser logins with a default `/web-route` route, administrator approval, and a three-failure IP block.

== First setup ==

1. Install and activate the plugin.
2. Open Settings → Web Route while already authenticated.
3. Select at least one eligible approver.
4. Configure SMTP or another reliable `wp_mail()` transport.
5. Send the test email.
6. Visit the displayed `/web-route` URL over HTTPS.
7. Enable protection and keep the recovery procedure available.

Use the Security page image setting to choose a site-specific logo for the login and security screens. Web Route detects a theme color from the logo, lets you fine-tune it, and uses the image as a watermark on its 404 screen. If no image is selected, Web Route uses the WordPress Site Icon when available.

The default protected accounts are users with `manage_options`; on Multisite, network super administrators are protected. The failure threshold is fixed at three attempts and the block duration is fixed at one hour.

Application passwords for protected users are disabled by default while Web Route is enabled. Re-enable them only for an integration that has been reviewed and tested.

== Recovery ==

If the approval email or route is unavailable, add this line to `wp-config.php`, regain access, and remove it immediately:

`define( 'RAIN_SECURITY_RECOVERY_MODE', true );`

WP-CLI is also available:

`wp rain-security status`

`wp rain-security disable`

`wp rain-security enable`

`wp rain-security expire`

`wp rain-security purge --days=30`

== Privacy and deployment ==

Login requests contain a short-lived display IP and security audit data. Review the site's privacy policy and retention requirements. The plugin reduces common WordPress discovery signals but cannot make a WordPress installation undetectable; configure server headers, disable directory indexes, protect backups, keep software updated, and use a WAF where appropriate.

== Development ==

See `IMPLEMENTATION_PLAN.md` for architecture, threat model, compatibility decisions, and the test matrix.
