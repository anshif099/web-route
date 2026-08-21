<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Config {
	const OPTION_NAME = 'rain_security_settings';

	public function defaults() {
		return array(
			'enabled'              => 0,
			'route'                => 'web-route',
			'approver_ids'         => array(),
			'email_tested_at'      => 0,
			'request_ttl'          => 10 * MINUTE_IN_SECONDS,
			'failure_limit'        => 3,
			'failure_window'       => 15 * MINUTE_IN_SECONDS,
			'block_duration'       => HOUR_IN_SECONDS,
			'bind_request_ip'      => 0,
			'trusted_proxy_cidrs'  => '',
			'trusted_proxy_header' => '',
			'audit_retention_days' => 30,
			'hide_discovery_links' => 1,
			'restrict_rest_users'  => 1,
			'block_author_enum'    => 1,
			'disable_xmlrpc_auth'  => 1,
			'disable_application_passwords' => 1,
			'remove_on_uninstall'  => 0,
		);
	}

	public function all() {
		$stored = is_multisite()
			? get_site_option( self::OPTION_NAME, array() )
			: get_option( self::OPTION_NAME, array() );

		return wp_parse_args( is_array( $stored ) ? $stored : array(), $this->defaults() );
	}

	public function get( $key, $fallback = null ) {
		$settings = $this->all();
		return array_key_exists( $key, $settings ) ? $settings[ $key ] : $fallback;
	}

	public function update( array $settings ) {
		$settings = wp_parse_args( $settings, $this->defaults() );
		if ( is_multisite() ) {
			return update_site_option( self::OPTION_NAME, $settings );
		}

		return update_option( self::OPTION_NAME, $settings, false );
	}

	public function is_recovery_mode() {
		return defined( 'RAIN_SECURITY_RECOVERY_MODE' ) && true === RAIN_SECURITY_RECOVERY_MODE;
	}

	public function is_enabled() {
		return ! $this->is_recovery_mode() && 1 === (int) $this->get( 'enabled', 0 );
	}

	public function route() {
		$route = (string) $this->get( 'route', 'web-route' );
		$route = preg_replace( '/[^A-Za-z0-9_-]/', '', $route );
		return '' !== $route ? $route : 'web-route';
	}

	public function route_url( array $args = array() ) {
		$url = set_url_scheme( home_url( '/' . rawurlencode( $this->route() ) . '/' ), 'https' );
		return $args ? add_query_arg( $args, $url ) : $url;
	}

	public function table( $name ) {
		global $wpdb;
		$prefix = is_multisite() ? $wpdb->base_prefix : $wpdb->prefix;
		return $prefix . 'rain_' . $name;
	}

	public function approver_ids() {
		$ids = array_filter( array_map( 'absint', (array) $this->get( 'approver_ids', array() ) ) );
		$ids = array_values( array_filter( $ids, array( $this, 'is_eligible_approver_id' ) ) );

		if ( $ids ) {
			return array_values( array_unique( $ids ) );
		}

		if ( is_multisite() ) {
			foreach ( (array) get_super_admins() as $login ) {
				$user = get_user_by( 'login', $login );
				if ( $user ) {
					$ids[] = (int) $user->ID;
				}
			}
		} else {
			$ids = get_users(
				array(
					'role'   => 'administrator',
					'fields' => 'ID',
				)
			);
		}

		return array_values( array_unique( array_map( 'absint', $ids ) ) );
	}

	public function is_eligible_approver_id( $user_id ) {
		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		if ( is_multisite() ) {
			return is_super_admin( $user_id );
		}

		return user_can( $user_id, 'manage_options' );
	}

	public function can_current_user_approve() {
		$user_id = get_current_user_id();
		return $user_id && in_array( $user_id, $this->approver_ids(), true );
	}

	public function is_protected_user( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return false;
		}

		$protected = is_multisite()
			? is_super_admin( $user->ID )
			: user_can( $user, 'manage_options' );

		return (bool) apply_filters( 'rain_security_is_protected_user', $protected, $user );
	}

	public function sanitized_settings( array $input ) {
		$current = $this->all();
		$route   = isset( $input['route'] ) ? preg_replace( '/[^A-Za-z0-9_-]/', '', (string) wp_unslash( $input['route'] ) ) : $current['route'];
		$route   = '' !== $route ? substr( $route, 0, 48 ) : 'web-route';
		$header  = isset( $input['trusted_proxy_header'] ) ? strtoupper( sanitize_key( wp_unslash( $input['trusted_proxy_header'] ) ) ) : '';
		$allowed_headers = array( '', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' );

		if ( ! in_array( $header, $allowed_headers, true ) ) {
			$header = '';
		}

		return array(
			'enabled'              => empty( $input['enabled'] ) ? 0 : 1,
			'route'                => $route,
			'approver_ids'         => array_values( array_filter( array_map( 'absint', isset( $input['approver_ids'] ) ? (array) $input['approver_ids'] : array() ) ) ),
			'email_tested_at'      => absint( $current['email_tested_at'] ),
			'request_ttl'          => min( HOUR_IN_SECONDS, max( 120, absint( $input['request_ttl'] ?? 600 ) ) ),
			'failure_limit'        => 3,
			'failure_window'       => min( DAY_IN_SECONDS, max( 60, absint( $input['failure_window'] ?? 900 ) ) ),
			'block_duration'       => HOUR_IN_SECONDS,
			'bind_request_ip'      => empty( $input['bind_request_ip'] ) ? 0 : 1,
			'trusted_proxy_cidrs'  => sanitize_textarea_field( wp_unslash( $input['trusted_proxy_cidrs'] ?? '' ) ),
			'trusted_proxy_header' => $header,
			'audit_retention_days' => min( 365, max( 1, absint( $input['audit_retention_days'] ?? 30 ) ) ),
			'hide_discovery_links' => empty( $input['hide_discovery_links'] ) ? 0 : 1,
			'restrict_rest_users'  => empty( $input['restrict_rest_users'] ) ? 0 : 1,
			'block_author_enum'    => empty( $input['block_author_enum'] ) ? 0 : 1,
			'disable_xmlrpc_auth'  => empty( $input['disable_xmlrpc_auth'] ) ? 0 : 1,
			'disable_application_passwords' => array_key_exists( 'disable_application_passwords', $input ) ? ( empty( $input['disable_application_passwords'] ) ? 0 : 1 ) : (int) $current['disable_application_passwords'],
			'remove_on_uninstall'  => empty( $input['remove_on_uninstall'] ) ? 0 : 1,
		);
	}
}
