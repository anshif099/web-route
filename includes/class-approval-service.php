<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Approval_Service {
	private $config;
	private $repository;
	private $ip;

	public function __construct( Config $config, Request_Repository $repository, Client_IP $ip ) {
		$this->config     = $config;
		$this->repository = $repository;
		$this->ip         = $ip;
	}

	public function create( \WP_User $user, $redirect_to, $remember_me ) {
		$client  = $this->ip->current();
		$public  = bin2hex( random_bytes( 16 ) );
		$verify  = bin2hex( random_bytes( 32 ) );
		$approve = bin2hex( random_bytes( 32 ) );
		$deny    = bin2hex( random_bytes( 32 ) );
		$now     = time();
		$expires = $now + max( 120, (int) $this->config->get( 'request_ttl', 600 ) );
		$ua      = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		$data = array(
			'public_id'          => $public,
			'user_id'            => (int) $user->ID,
			'ip_hash'            => $client['hash'],
			'ip_display'         => substr( $client['address'], 0, 45 ),
			'user_agent_hash'    => hash_hmac( 'sha256', $ua, wp_salt( 'auth' ) ),
			'browser_summary'    => substr( $this->browser_summary( $ua ), 0, 191 ),
			'verifier_hash'      => hash_hmac( 'sha256', $verify, wp_salt( 'nonce' ) ),
			'approve_token_hash' => hash_hmac( 'sha256', $approve, wp_salt( 'auth' ) ),
			'deny_token_hash'    => hash_hmac( 'sha256', $deny, wp_salt( 'auth' ) ),
			'redirect_to'        => $this->safe_redirect( $redirect_to ),
			'remember_me'        => $remember_me ? 1 : 0,
			'status'             => 'pending',
			'created_at'         => gmdate( 'Y-m-d H:i:s', $now ),
			'expires_at'         => gmdate( 'Y-m-d H:i:s', $expires ),
		);

		$id = $this->repository->create( $data );
		if ( ! $id ) {
			return new \WP_Error( 'rain_request_create_failed', __( 'The security request could not be created. Please use the recovery procedure.', 'rain-admin-login-security' ) );
		}

		$request = (object) array_merge( $data, array( 'id' => $id ) );
		$this->send_notifications( $request, $user, $approve, $deny );
		$this->repository->audit(
			'approval_requested',
			array(
				'request_id' => $public,
				'user_id'    => $user->ID,
				'ip_hash'    => $client['hash'],
				'result'     => 'pending',
				'details'    => array( 'expires_at' => $data['expires_at'] ),
			)
		);

		return array(
			'public_id'  => $public,
			'verifier'   => $verify,
			'expires_at' => $expires,
			'redirect_to' => $data['redirect_to'],
		);
	}

	public function status( $public_id, $verifier, $client_address = null ) {
		$request = $this->repository->get( $public_id );
		if ( ! $request || ! $this->valid_verifier( $request, $verifier ) ) {
			return array( 'status' => 'invalid' );
		}
		if ( strtotime( $request->expires_at . ' UTC' ) <= time() && in_array( $request->status, array( 'pending', 'approved' ), true ) ) {
			$this->repository->expire();
			return array( 'status' => 'expired' );
		}
		if ( $this->config->get( 'bind_request_ip', 0 ) && null !== $client_address ) {
			$client_hash = hash_hmac( 'sha256', (string) $client_address, wp_salt( 'auth' ) );
			if ( ! hash_equals( (string) $request->ip_hash, $client_hash ) ) {
				return array( 'status' => 'invalid' );
			}
		}

		$status = in_array( $request->status, array( 'pending', 'approved', 'denied', 'consumed', 'expired', 'cancelled' ), true ) ? $request->status : 'invalid';
		return array( 'status' => $status );
	}

	public function exchange( $public_id, $verifier, $client_address = null ) {
		$request = $this->repository->get( $public_id );
		if ( ! $request || ! $this->valid_verifier( $request, $verifier ) || 'approved' !== $request->status ) {
			return new \WP_Error( 'rain_exchange_invalid', __( 'This approval is no longer valid.', 'rain-admin-login-security' ) );
		}
		if ( $this->config->get( 'bind_request_ip', 0 ) && null !== $client_address ) {
			$client_hash = hash_hmac( 'sha256', (string) $client_address, wp_salt( 'auth' ) );
			if ( ! hash_equals( (string) $request->ip_hash, $client_hash ) ) {
				return new \WP_Error( 'rain_exchange_invalid', __( 'This approval is no longer valid.', 'rain-admin-login-security' ) );
			}
		}
		$user = get_user_by( 'id', (int) $request->user_id );
		if ( ! $user || ! $this->config->is_protected_user( $user ) ) {
			return new \WP_Error( 'rain_user_invalid', __( 'This account is not eligible for Web Route login.', 'rain-admin-login-security' ) );
		}
		if ( ! $this->repository->consume( $public_id, hash_hmac( 'sha256', $verifier, wp_salt( 'nonce' ) ) ) ) {
			return new \WP_Error( 'rain_exchange_used', __( 'This approval has already been used.', 'rain-admin-login-security' ) );
		}
		$this->repository->audit( 'approval_consumed', array( 'request_id' => $public_id, 'user_id' => $user->ID, 'ip_hash' => $request->ip_hash, 'result' => 'success' ) );
		return array( 'user' => $user, 'request' => $request );
	}

	public function decide_by_token( $public_id, $token, $action ) {
		$column = 'approve' === $action ? 'approve_token_hash' : 'deny_token_hash';
		$request = $this->repository->get_by_token( $column, hash_hmac( 'sha256', $token, wp_salt( 'auth' ) ) );
		if ( ! $request || ! hash_equals( (string) $request->{$column}, hash_hmac( 'sha256', $token, wp_salt( 'auth' ) ) ) || $request->public_id !== $public_id ) {
			return new \WP_Error( 'rain_decision_invalid', __( 'This approval link is invalid or expired.', 'rain-admin-login-security' ) );
		}
		if ( ! $this->repository->decide( $public_id, 'approve' === $action ? 'approved' : 'denied', 0, 'email' ) ) {
			return new \WP_Error( 'rain_decision_taken', __( 'This request has already been decided or expired.', 'rain-admin-login-security' ) );
		}
		$this->repository->audit( 'approval_decision', array( 'request_id' => $public_id, 'user_id' => $request->user_id, 'ip_hash' => $request->ip_hash, 'result' => $action, 'details' => array( 'method' => 'email' ) ) );
		return true;
	}

	public function decide_by_user( $public_id, $user_id, $action ) {
		if ( ! $this->config->can_current_user_approve() || ! in_array( $action, array( 'approve', 'deny' ), true ) ) {
			return new \WP_Error( 'rain_not_authorized', __( 'You are not authorized to decide this request.', 'rain-admin-login-security' ) );
		}
		$request = $this->repository->get( $public_id );
		if ( ! $request ) {
			return new \WP_Error( 'rain_request_missing', __( 'The request was not found.', 'rain-admin-login-security' ) );
		}
		$approvers = $this->config->approver_ids();
		if ( count( $approvers ) > 1 && (int) $request->user_id === (int) $user_id ) {
			return new \WP_Error( 'rain_self_approval', __( 'A different approver must decide this request.', 'rain-admin-login-security' ) );
		}
		if ( ! $this->repository->decide( $public_id, 'approve' === $action ? 'approved' : 'denied', $user_id, 'dashboard' ) ) {
			return new \WP_Error( 'rain_decision_taken', __( 'This request has already been decided or expired.', 'rain-admin-login-security' ) );
		}
		$this->repository->audit( 'approval_decision', array( 'request_id' => $public_id, 'user_id' => $request->user_id, 'actor_id' => $user_id, 'ip_hash' => $request->ip_hash, 'result' => $action, 'details' => array( 'method' => 'dashboard' ) ) );
		return true;
	}

	public function pending( $limit = 50 ) {
		return $this->repository->pending( $limit );
	}

	private function valid_verifier( $request, $verifier ) {
		$verifier = preg_replace( '/[^a-f0-9]/', '', strtolower( (string) $verifier ) );
		return 64 === strlen( $verifier ) && hash_equals( (string) $request->verifier_hash, hash_hmac( 'sha256', $verifier, wp_salt( 'nonce' ) ) );
	}

	private function send_notifications( $request, \WP_User $user, $approve, $deny ) {
		$recipients = array();
		foreach ( $this->config->approver_ids() as $approver_id ) {
			$approver = get_user_by( 'id', $approver_id );
			if ( $approver && is_email( $approver->user_email ) ) {
				$recipients[] = $approver->user_email;
			}
		}
		$recipients = array_values( array_unique( $recipients ) );
		if ( ! $recipients ) {
			return false;
		}

		$base = $this->config->route_url();
		$approve_url = add_query_arg( array( 'action' => 'approve', 'request' => $request->public_id, 'token' => $approve ), $base );
		$deny_url    = add_query_arg( array( 'action' => 'deny', 'request' => $request->public_id, 'token' => $deny ), $base );
		$subject = sprintf( __( '[%s] Admin login approval requested', 'rain-admin-login-security' ), sanitize_text_field( wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ) );
		$body = sprintf(
			"A protected admin login needs approval.\n\nAccount: %s\nIP: %s\nBrowser: %s\nExpires: %s UTC\n\nApprove: %s\nDeny: %s\n\nOpening a link only shows a confirmation page; it does not log anyone in.",
			$user->user_login,
			$request->ip_display,
			$request->browser_summary ? $request->browser_summary : 'Unknown',
			$request->expires_at,
			$approve_url,
			$deny_url
		);
		return wp_mail( $recipients, $subject, $body );
	}

	private function browser_summary( $ua ) {
		if ( ! $ua ) {
			return 'Unknown browser';
		}
		$browser = 'Browser';
		if ( false !== stripos( $ua, 'Edg/' ) ) {
			$browser = 'Edge';
		} elseif ( false !== stripos( $ua, 'Chrome/' ) ) {
			$browser = 'Chrome';
		} elseif ( false !== stripos( $ua, 'Firefox/' ) ) {
			$browser = 'Firefox';
		} elseif ( false !== stripos( $ua, 'Safari/' ) ) {
			$browser = 'Safari';
		}
		$platform = false !== stripos( $ua, 'Windows' ) ? 'Windows' : ( false !== stripos( $ua, 'Mac OS' ) ? 'macOS' : ( false !== stripos( $ua, 'Linux' ) ? 'Linux' : 'Other OS' ) );
		return $browser . ' on ' . $platform;
	}

	private function safe_redirect( $redirect ) {
		$redirect = is_string( $redirect ) ? $redirect : '';
		return wp_validate_redirect( $redirect, admin_url() );
	}
}
