<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Hardening {
	private $config;

	public function __construct( Config $config ) {
		$this->config = $config;
	}

	public function register_hooks() {
		if ( ! $this->config->is_enabled() ) {
			return;
		}
		if ( $this->config->get( 'hide_discovery_links', 1 ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			remove_action( 'wp_head', 'rsd_link' );
			remove_action( 'wp_head', 'wlwmanifest_link' );
			remove_action( 'wp_head', 'wp_shortlink_wp_head' );
			remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
			remove_action( 'wp_head', 'wp_oembed_add_host_js' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'wp_headers', array( $this, 'headers' ) );
		}
		if ( $this->config->get( 'restrict_rest_users', 1 ) ) {
			add_filter( 'rest_endpoints', array( $this, 'rest_endpoints' ) );
		}
		if ( $this->config->get( 'block_author_enum', 1 ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_query' ), 0 );
		}
		if ( $this->config->get( 'disable_xmlrpc_auth', 1 ) ) {
			add_filter( 'authenticate', array( $this, 'block_xmlrpc_protected_auth' ), 100, 3 );
		}
		if ( $this->config->get( 'disable_application_passwords', 1 ) ) {
			add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'application_passwords_available' ), 10, 2 );
		}
		add_filter( 'login_errors', array( $this, 'generic_login_error' ) );
	}

	public function headers( $headers ) {
		$headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive';
		return $headers;
	}

	public function rest_endpoints( $endpoints ) {
		if ( is_user_logged_in() || ! is_array( $endpoints ) ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $endpoint ) {
			if ( preg_match( '#/wp/v2/(?:users|plugins|themes)(?:/|$)#', $endpoint ) ) {
				unset( $endpoints[ $endpoint ] );
			}
		}
		return $endpoints;
	}

	public function block_author_query() {
		if ( isset( $_GET['author'] ) && ! is_user_logged_in() ) {
			status_header( 404 );
			nocache_headers();
			wp_die( esc_html__( 'Not found.', 'rain-admin-login-security' ), '', array( 'response' => 404 ) );
		}
	}

	public function block_xmlrpc_protected_auth( $user, $username, $password ) {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $user instanceof \WP_User && $this->config->is_protected_user( $user ) ) {
			return new \WP_Error( 'rain_approval_required', __( 'Administrator approval is required for this login.', 'rain-admin-login-security' ) );
		}
		return $user;
	}

	public function application_passwords_available( $available, $user ) {
		if ( $available && $user instanceof \WP_User && $this->config->is_protected_user( $user ) ) {
			return false;
		}
		return $available;
	}

	public function generic_login_error( $error ) {
		if ( false !== strpos( strtolower( wp_strip_all_tags( (string) $error ) ), 'incorrect' ) || false !== strpos( strtolower( wp_strip_all_tags( (string) $error ) ), 'invalid' ) ) {
			return __( 'The username or password is incorrect.', 'rain-admin-login-security' );
		}
		return $error;
	}
}
