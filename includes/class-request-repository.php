<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Request_Repository {
	private $config;

	public function __construct( Config $config ) {
		$this->config = $config;
	}

	public function create( array $data ) {
		global $wpdb;
		$ok = $wpdb->insert(
			$this->config->table( 'login_requests' ),
			$data,
			array( '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
		);
		return $ok ? (int) $wpdb->insert_id : 0;
	}

	public function get( $public_id ) {
		global $wpdb;
		$public_id = strtolower( preg_replace( '/[^a-f0-9]/', '', (string) $public_id ) );
		if ( 32 !== strlen( $public_id ) ) {
			return null;
		}
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->config->table( 'login_requests' )} WHERE public_id = %s LIMIT 1", $public_id ) );
	}

	public function get_by_token( $column, $token_hash ) {
		global $wpdb;
		$allowed = array( 'approve_token_hash', 'deny_token_hash' );
		if ( ! in_array( $column, $allowed, true ) ) {
			return null;
		}
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->config->table( 'login_requests' )} WHERE {$column} = %s LIMIT 1", $token_hash ) );
	}

	public function pending( $limit = 50 ) {
		global $wpdb;
		$limit = min( 100, max( 1, absint( $limit ) ) );
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->config->table( 'login_requests' )} WHERE status = 'pending' AND expires_at > %s ORDER BY created_at DESC LIMIT %d", gmdate( 'Y-m-d H:i:s' ), $limit ) );
	}

	public function recent( $limit = 50 ) {
		global $wpdb;
		$limit = min( 100, max( 1, absint( $limit ) ) );
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->config->table( 'login_requests' )} ORDER BY created_at DESC LIMIT %d", $limit ) );
	}

	public function decide( $public_id, $status, $actor_id = 0, $method = 'dashboard' ) {
		global $wpdb;
		if ( ! in_array( $status, array( 'approved', 'denied' ), true ) ) {
			return false;
		}
		$now = gmdate( 'Y-m-d H:i:s' );
		return (bool) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$this->config->table( 'login_requests' )} SET status = %s, decided_at = %s, decided_by = %d, decision_method = %s WHERE public_id = %s AND status = 'pending' AND expires_at > %s",
				$status,
				$now,
				absint( $actor_id ),
				 sanitize_key( $method ),
				$public_id,
				$now
			)
		);
	}

	public function consume( $public_id, $verifier_hash ) {
		global $wpdb;
		$now = gmdate( 'Y-m-d H:i:s' );
		$updated = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$this->config->table( 'login_requests' )} SET status = 'consumed', consumed_at = %s WHERE public_id = %s AND verifier_hash = %s AND status = 'approved' AND expires_at > %s",
				$now,
				$public_id,
				$verifier_hash,
				$now
			)
		);
		return 1 === (int) $updated;
	}

	public function expire() {
		global $wpdb;
		$now = gmdate( 'Y-m-d H:i:s' );
		return $wpdb->query( $wpdb->prepare( "UPDATE {$this->config->table( 'login_requests' )} SET status = 'expired' WHERE status = 'pending' AND expires_at <= %s", $now ) );
	}

	public function cancel_for_user( $user_id ) {
		global $wpdb;
		return $wpdb->query( $wpdb->prepare( "UPDATE {$this->config->table( 'login_requests' )} SET status = 'cancelled' WHERE user_id = %d AND status = 'pending'", absint( $user_id ) ) );
	}

	public function purge( $days ) {
		global $wpdb;
		$days = max( 1, absint( $days ) );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( DAY_IN_SECONDS * $days ) );
		$requests = $wpdb->query( $wpdb->prepare( "DELETE FROM {$this->config->table( 'login_requests' )} WHERE created_at < %s", $cutoff ) );
		$events = $wpdb->query( $wpdb->prepare( "DELETE FROM {$this->config->table( 'audit_events' )} WHERE created_at < %s", $cutoff ) );
		return array( 'requests' => (int) $requests, 'events' => (int) $events );
	}

	public function audit( $event_type, array $data = array() ) {
		global $wpdb;
		$wpdb->insert(
			$this->config->table( 'audit_events' ),
			array(
				'event_type' => sanitize_key( $event_type ),
				'request_id' => isset( $data['request_id'] ) ? sanitize_text_field( $data['request_id'] ) : null,
				'user_id'    => isset( $data['user_id'] ) ? absint( $data['user_id'] ) : null,
				'actor_id'   => isset( $data['actor_id'] ) ? absint( $data['actor_id'] ) : null,
				'ip_hash'    => isset( $data['ip_hash'] ) ? sanitize_text_field( $data['ip_hash'] ) : null,
				'result'     => isset( $data['result'] ) ? sanitize_key( $data['result'] ) : '',
				'details'    => isset( $data['details'] ) ? wp_json_encode( $data['details'] ) : null,
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s' )
		);
	}
}
