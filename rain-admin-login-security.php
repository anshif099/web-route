<?php
/**
 * Plugin Name: web-route
 * Plugin URI:  https://example.com/rain-admin-login-security
 * Description: Protects privileged WordPress logins with administrator approval, IP rate limiting, a custom login route, and conservative fingerprint reduction.
 * Version:     0.3.0
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * Author:      Rainhopes
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: rain-admin-login-security
 */

defined( 'ABSPATH' ) || exit;

define( 'RAIN_SECURITY_VERSION', '0.3.0' );
define( 'RAIN_SECURITY_FILE', __FILE__ );
define( 'RAIN_SECURITY_DIR', plugin_dir_path( __FILE__ ) );

require_once RAIN_SECURITY_DIR . 'includes/class-config.php';
require_once RAIN_SECURITY_DIR . 'includes/class-installer.php';
require_once RAIN_SECURITY_DIR . 'includes/class-client-ip.php';
require_once RAIN_SECURITY_DIR . 'includes/class-rate-limiter.php';
require_once RAIN_SECURITY_DIR . 'includes/class-request-repository.php';
require_once RAIN_SECURITY_DIR . 'includes/class-approval-service.php';
require_once RAIN_SECURITY_DIR . 'includes/class-router.php';
require_once RAIN_SECURITY_DIR . 'includes/class-admin.php';
require_once RAIN_SECURITY_DIR . 'includes/class-hardening.php';
require_once RAIN_SECURITY_DIR . 'includes/class-cli.php';
require_once RAIN_SECURITY_DIR . 'includes/class-plugin.php';

register_activation_hook( __FILE__, array( 'Rain\\Security\\Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Rain\\Security\\Installer', 'deactivate' ) );

Rain\Security\Plugin::instance()->register_hooks();
