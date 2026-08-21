<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Rate_Limiter {
	private $config;
	private $ip;

	public function __construct( Config $config, Client_IP $ip ) {
		$this->config = $config;
		$this->ip     = $ip;
	}

	public function status( $address = null ) {
		if ( null === $address ) {
			$client  = $this->ip->current();
			$address = $client['address'];
			$hash    = $client['hash'];
		} else {
			$hash = hash_hmac( 'sha256', (string) $address, wp_salt( 'auth' ) );
		}

		$row = $this->get_row( $hash );
		if ( ! $row ) {
			return array(
				'blocked'       => false,
				'failed_count'  => 0,
				'blocked_until' => 0,
				'remaining'     => 0,
				'ip'            => $address,
				'hash'          => $hash,
			);
		}

		$until = empty( $row->blocked_until ) ? 0 : strtotime( $row->blocked_until . ' UTC' );
		if ( $until && $until <= time() ) {
			$this->clear_hash( $hash );
			$until = 0;
			$row   = null;
		}

		return array(
			'blocked'       => $until > time(),
			'failed_count'  => $row ? (int) $row->failed_count : 0,
			'blocked_until' => $until,
			'remaining'     => $until > time() ? max( 0, $until - time() ) : 0,
			'ip'            => $address,
			'hash'          => $hash,
		);
	}

	/**
	 * Record one failed credential attempt. A short transaction prevents
	 * simultaneous requests from racing past the third-failure boundary.
	 */
	public function record_failure( $address = null ) {
		global $wpdb;

		$client = null;
		if ( null === $address ) {
			$client  = $this->ip->current();
			$address = $client['address'];
			$hash    = $client['hash'];
		} else {
			$address = (string) $address;
			$hash    = hash_hmac( 'sha256', $address, wp_salt( 'auth' ) );
		}

		$table       = $this->config->table( 'rate_limits' );
		$now         = time();
		$now_sql     = gmdate( 'Y-m-d H:i:s', $now );
		$window      = max( 60, (int) $this->config->get( 'failure_window', 900 ) );
		$block       = max( 60, (int) $this->config->get( 'block_duration', HOUR_IN_SECONDS ) );
		$limit       = 3;
		$failed      = 1;
		$blocked_end = 0;

		$wpdb->query( 'START TRANSACTION' );
		// Materialize the row before locking it. INSERT IGNORE serializes the
		// first request for a new IP on the primary key, avoiding a reset race.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$table} (ip_hash, failed_count, window_started, last_failure, blocked_until) VALUES (%s, 0, %s, %s, NULL)",
				$hash,
				$now_sql,
				$now_sql
			)
		);
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE ip_hash = %s FOR UPDATE", $hash ) );
		if ( ! $row ) {
			$wpdb->query( 'ROLLBACK' );
			// If the security table is unavailable, fail closed for this login
			// attempt instead of allowing an untracked retry.
			return array(
				'blocked'       => true,
				'failed_count'  => 0,
				'blocked_until' => $now + $block,
				'remaining'     => $block,
				'ip'            => $address,
				'hash'          => $hash,
			);
		}

		if ( $row && ! empty( $row->blocked_until ) && strtotime( $row->blocked_until . ' UTC' ) > $now ) {
			$blocked_end = strtotime( $row->blocked_until . ' UTC' );
			$failed      = (int) $row->failed_count;
		} elseif ( $row && strtotime( $row->window_started . ' UTC' ) + $window <= $now ) {
			$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET failed_count = 1, window_started = %s, last_failure = %s, blocked_until = NULL WHERE ip_hash = %s", $now_sql, $now_sql, $hash ) );
			$failed = 1;
		} else {
			$failed = (int) $row->failed_count + 1;
			$blocked_end = $failed >= $limit ? $now + $block : 0;
			if ( $blocked_end ) {
				$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET failed_count = %d, last_failure = %s, blocked_until = %s WHERE ip_hash = %s", $failed, $now_sql, gmdate( 'Y-m-d H:i:s', $blocked_end ), $hash ) );
			} else {
				$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET failed_count = %d, last_failure = %s, blocked_until = NULL WHERE ip_hash = %s", $failed, $now_sql, $hash ) );
			}
		}
		$wpdb->query( 'COMMIT' );

		return array(
			'blocked'       => $blocked_end > $now,
			'failed_count'  => $failed,
			'blocked_until' => $blocked_end,
			'remaining'     => $blocked_end > $now ? $blocked_end - $now : 0,
			'ip'            => $address,
			'hash'          => $hash,
		);
	}

	public function clear( $address = null ) {
		if ( null === $address ) {
			$hash = $this->ip->hash();
		} else {
			$hash = hash_hmac( 'sha256', (string) $address, wp_salt( 'auth' ) );
		}
		return $this->clear_hash( $hash );
	}

	public function clear_hash( $hash ) {
		global $wpdb;
		return (bool) $wpdb->delete( $this->config->table( 'rate_limits' ), array( 'ip_hash' => $hash ), array( '%s' ) );
	}

	public function purge_expired() {
		global $wpdb;
		$now = gmdate( 'Y-m-d H:i:s' );
		return $wpdb->query( $wpdb->prepare( "DELETE FROM {$this->config->table( 'rate_limits' )} WHERE (blocked_until IS NOT NULL AND blocked_until < %s) OR (window_started < DATE_SUB(%s, INTERVAL %d SECOND) AND (blocked_until IS NULL OR blocked_until < %s))", $now, $now, max( 60, (int) $this->config->get( 'failure_window', 900 ) ), $now ) );
	}

	private function get_row( $hash ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->config->table( 'rate_limits' )} WHERE ip_hash = %s", $hash ) );
	}
}
