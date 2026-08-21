<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Installer {
	const DB_VERSION = '1.1.0';
	const DB_OPTION  = 'rain_security_db_version';

	public static function activate() {
		$config = new Config();
		self::migrate_legacy_default_route( $config );
		self::create_tables( $config );

		$existing = is_multisite()
			? get_site_option( Config::OPTION_NAME, null )
			: get_option( Config::OPTION_NAME, null );

		if ( ! is_array( $existing ) ) {
			$config->update( $config->defaults() );
		}

		add_rewrite_rule( '^' . preg_quote( $config->route(), '#' ) . '/?$', 'index.php?rain_security=1', 'top' );
		flush_rewrite_rules();
	}

	public static function deactivate() {
		$timestamp = wp_next_scheduled( 'rain_security_cleanup' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'rain_security_cleanup' );
		}
		flush_rewrite_rules();
	}

	public static function maybe_upgrade() {
		$installed = is_multisite()
			? get_site_option( self::DB_OPTION, '' )
			: get_option( self::DB_OPTION, '' );

		if ( self::DB_VERSION !== $installed ) {
			$config        = new Config();
			$route_changed = self::migrate_legacy_default_route( $config );
			self::create_tables( $config );

			if ( $route_changed ) {
				add_rewrite_rule( '^' . preg_quote( $config->route(), '#' ) . '/?$', 'index.php?rain_security=1', 'top' );
				flush_rewrite_rules();
			}
		}
	}

	private static function migrate_legacy_default_route( Config $config ) {
		if ( 'Rain' !== $config->route() ) {
			return false;
		}

		$settings          = $config->all();
		$settings['route'] = 'web-route';
		$config->update( $settings );
		return true;
	}

	private static function create_tables( Config $config ) {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$collate  = $wpdb->get_charset_collate();
		$requests = $config->table( 'login_requests' );
		$limits   = $config->table( 'rate_limits' );
		$audit    = $config->table( 'audit_events' );

		$sql_requests = "CREATE TABLE {$requests} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			public_id char(32) NOT NULL,
			user_id bigint(20) unsigned NOT NULL,
			ip_hash char(64) NOT NULL,
			ip_display varchar(45) NOT NULL DEFAULT '',
			user_agent_hash char(64) NOT NULL,
			browser_summary varchar(191) NOT NULL DEFAULT '',
			verifier_hash char(64) NOT NULL,
			approve_token_hash char(64) NOT NULL,
			deny_token_hash char(64) NOT NULL,
			redirect_to text NULL,
			remember_me tinyint(1) unsigned NOT NULL DEFAULT 0,
			status varchar(20) NOT NULL DEFAULT 'pending',
			created_at datetime NOT NULL,
			expires_at datetime NOT NULL,
			decided_at datetime NULL,
			consumed_at datetime NULL,
			decided_by bigint(20) unsigned NULL,
			decision_method varchar(20) NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY public_id (public_id),
			KEY status_expires (status,expires_at),
			KEY user_status (user_id,status),
			KEY approve_token (approve_token_hash),
			KEY deny_token (deny_token_hash)
		) {$collate};";

		$sql_limits = "CREATE TABLE {$limits} (
			ip_hash char(64) NOT NULL,
			failed_count smallint(5) unsigned NOT NULL DEFAULT 0,
			window_started datetime NOT NULL,
			last_failure datetime NOT NULL,
			blocked_until datetime NULL,
			PRIMARY KEY  (ip_hash),
			KEY blocked_until (blocked_until)
		) {$collate};";

		$sql_audit = "CREATE TABLE {$audit} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			event_type varchar(64) NOT NULL,
			request_id char(32) NULL,
			user_id bigint(20) unsigned NULL,
			actor_id bigint(20) unsigned NULL,
			ip_hash char(64) NULL,
			result varchar(32) NOT NULL DEFAULT '',
			details text NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY created_at (created_at),
			KEY event_type (event_type),
			KEY request_id (request_id)
		) {$collate};";

		dbDelta( $sql_requests );
		dbDelta( $sql_limits );
		dbDelta( $sql_audit );

		if ( is_multisite() ) {
			update_site_option( self::DB_OPTION, self::DB_VERSION );
		} else {
			update_option( self::DB_OPTION, self::DB_VERSION, false );
		}
	}
}
