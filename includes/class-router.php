<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Router {
	private $config;
	private $ip;
	private $limiter;
	private $repository;
	private $approval;
	private $credential_context = false;

	public function __construct( Config $config, Client_IP $ip, Rate_Limiter $limiter, Request_Repository $repository, Approval_Service $approval ) {
		$this->config     = $config;
		$this->ip         = $ip;
		$this->limiter    = $limiter;
		$this->repository = $repository;
		$this->approval   = $approval;
	}

	public function register_hooks() {
		add_action( 'init', array( $this, 'register_route' ), 1 );
		add_action( 'init', array( $this, 'intercept_admin_request' ), 0 );
		add_action( 'template_redirect', array( $this, 'handle_route' ), 0 );
		add_action( 'login_init', array( $this, 'intercept_core_login' ), 1 );
		add_filter( 'login_url', array( $this, 'login_url' ), 10, 3 );
		add_filter( 'lostpassword_url', array( $this, 'lostpassword_url' ), 10, 2 );
		add_filter( 'logout_url', array( $this, 'logout_url' ), 10, 2 );
		add_filter( 'register_url', array( $this, 'register_url' ), 10, 1 );
		add_filter( 'retrieve_password_message', array( $this, 'password_reset_message' ), 10, 4 );
		add_filter( 'authenticate', array( $this, 'authentication_gate' ), 99, 3 );
		add_action( 'rain_security_cleanup', array( $this, 'cleanup' ) );
		if ( ! wp_next_scheduled( 'rain_security_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'rain_security_cleanup' );
		}
	}

	public function register_route() {
		$route = preg_quote( $this->config->route(), '#' );
		add_rewrite_tag( '%rain_security%', '1' );
		add_rewrite_rule( '^' . $route . '/?$', 'index.php?rain_security=1', 'top' );
	}

	public function intercept_admin_request() {
		if ( ! $this->config->is_enabled() || $this->config->is_recovery_mode() || is_user_logged_in() || ! preg_match( '#(?:^|/)wp-admin(?:/|$)#i', $this->request_path() ) ) {
			return;
		}
		$path = $this->request_path();
		if ( preg_match( '#/wp-admin/(?:admin-ajax|admin-post)\.php$#i', $path ) ) {
			return;
		}
		$this->render_decoy( 404 );
	}

	public function intercept_core_login() {
		if ( ! $this->config->is_enabled() || $this->config->is_recovery_mode() || is_user_logged_in() ) {
			return;
		}
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
		if ( in_array( $action, array( 'rp', 'resetpass' ), true ) ) {
			$args = array( 'action' => 'resetpass' );
			foreach ( array( 'key', 'login' ) as $key ) {
				if ( isset( $_REQUEST[ $key ] ) ) {
					$args[ $key ] = sanitize_text_field( wp_unslash( $_REQUEST[ $key ] ) );
				}
			}
			wp_safe_redirect( $this->config->route_url( $args ) );
			exit;
		}
		$this->render_decoy( 404 );
	}

	public function login_url( $url, $redirect = '', $force_reauth = false ) {
		$args = array();
		if ( $redirect ) {
			$args['redirect_to'] = wp_validate_redirect( $redirect, admin_url() );
		}
		if ( $force_reauth ) {
			$args['reauth'] = 1;
		}
		return $this->config->route_url( $args );
	}

	public function lostpassword_url( $url, $redirect = '' ) {
		$args = array( 'action' => 'lostpassword' );
		if ( $redirect ) {
			$args['redirect_to'] = wp_validate_redirect( $redirect, home_url( '/' ) );
		}
		return $this->config->route_url( $args );
	}

	public function logout_url( $url, $redirect = '' ) {
		$args = array(
			'action'   => 'logout',
			'_wpnonce' => wp_create_nonce( 'log-out' ),
		);
		if ( $redirect ) {
			$args['redirect_to'] = wp_validate_redirect( $redirect, home_url( '/' ) );
		}
		return $this->config->route_url( $args );
	}

	public function register_url( $url ) {
		return $this->config->route_url( array( 'action' => 'register' ) );
	}

	public function password_reset_message( $message, $key, $user_login, $user_data ) {
		$url = $this->config->route_url(
			array(
				'action' => 'resetpass',
				'key'    => $key,
				'login'  => $user_login,
			)
		);
		return preg_replace( '#https?://[^\s]+#', $url, $message, 1 );
	}

	public function authentication_gate( $user, $username, $password ) {
		if ( ! $this->config->is_enabled() || $this->config->is_recovery_mode() || $this->credential_context || is_wp_error( $user ) || ! $user instanceof \WP_User || ! $this->config->is_protected_user( $user ) ) {
			return $user;
		}

		return new \WP_Error( 'rain_approval_required', __( 'Administrator approval is required for this login.', 'rain-admin-login-security' ) );
	}

	public function handle_route() {
		if ( ! $this->is_rain_request() ) {
			return;
		}

		if ( ! $this->config->is_enabled() ) {
			$this->render_page( __( 'Web Route setup required', 'rain-admin-login-security' ), '<p>' . esc_html__( 'Web Route login protection has not been enabled yet. An administrator must complete the setup checklist.', 'rain-admin-login-security' ) . '</p>', 503 );
		}

		$this->repository->expire();
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
		switch ( $action ) {
			case 'login':
				$this->handle_login();
				break;
			case 'status':
				$this->handle_status();
				break;
			case 'exchange':
				$this->handle_exchange();
				break;
			case 'approve':
			case 'deny':
				$this->handle_decision( $action );
				break;
			case 'logout':
				$this->handle_logout();
				break;
			case 'lostpassword':
				$this->handle_lostpassword();
				break;
			case 'resetpass':
				$this->handle_reset_password();
				break;
			case 'register':
				$this->handle_register();
				break;
			default:
				$this->render_login();
		}
	}

	public function cleanup() {
		$this->repository->expire();
		$this->repository->purge( $this->config->get( 'audit_retention_days', 30 ) );
		$this->limiter->purge_expired();
	}

	private function handle_login() {
		if ( 'POST' !== strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET' ) ) {
			$this->render_login();
		}
		if ( ! isset( $_POST['rain_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['rain_nonce'] ) ), 'rain_login' ) ) {
			$this->render_login( __( 'The login form expired. Please try again.', 'rain-admin-login-security' ) );
		}

		$limit = $this->limiter->status();
		if ( $limit['blocked'] ) {
			$this->render_blocked( $limit );
		}

		$username = isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '';
		$password = isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '';
		$remember = ! empty( $_POST['rememberme'] );
		$redirect = isset( $_POST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_POST['redirect_to'] ), admin_url() ) : admin_url();

		$this->credential_context = true;
		$user = wp_authenticate( $username, $password );
		$this->credential_context = false;

		if ( is_wp_error( $user ) ) {
			$failure = $this->limiter->record_failure();
			$this->repository->audit( 'login_failed', array( 'ip_hash' => $failure['hash'], 'result' => $failure['blocked'] ? 'blocked' : 'failed' ) );
			if ( $failure['blocked'] ) {
				$this->render_blocked( $failure );
			}
			$this->render_login( __( 'The username or password is incorrect.', 'rain-admin-login-security' ) );
		}

		$this->limiter->clear();
		if ( ! $this->config->is_protected_user( $user ) ) {
			$this->complete_login( $user, $remember, $redirect );
		}

		if ( ! $this->config->approver_ids() ) {
			$this->render_login( __( 'Web Route is awaiting administrator setup. Please use the recovery procedure.', 'rain-admin-login-security' ) );
		}

		$request = $this->approval->create( $user, $redirect, $remember );
		if ( is_wp_error( $request ) ) {
			$this->render_login( $request->get_error_message() );
		}
		$this->set_verifier_cookie( $request['verifier'] );
		$this->render_waiting( $request['public_id'], $request['expires_at'] );
	}

	private function handle_status() {
		nocache_headers();
		$public = isset( $_POST['request'] ) ? sanitize_text_field( wp_unslash( $_POST['request'] ) ) : '';
		$status = $this->approval->status( $public, $this->get_verifier(), $this->ip->current()['address'] );
		wp_send_json_success( $status );
	}

	private function handle_exchange() {
		nocache_headers();
		$public = isset( $_POST['request'] ) ? sanitize_text_field( wp_unslash( $_POST['request'] ) ) : '';
		$result = $this->approval->exchange( $public, $this->get_verifier(), $this->ip->current()['address'] );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'This approval is no longer valid.', 'rain-admin-login-security' ) ), 403 );
		}
		$this->clear_verifier_cookie();
		$user = $result['user'];
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, ! empty( $result['request']->remember_me ), is_ssl() );
		do_action( 'wp_login', $user->user_login, $user );
		wp_send_json_success( array( 'redirect' => wp_validate_redirect( $result['request']->redirect_to, admin_url() ) ) );
	}

	private function handle_decision( $action ) {
		$public = isset( $_REQUEST['request'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['request'] ) ) : '';
		$token  = isset( $_REQUEST['token'] ) ? preg_replace( '/[^a-f0-9]/', '', strtolower( wp_unslash( $_REQUEST['token'] ) ) ) : '';
		if ( 'POST' !== strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET' ) ) {
			$nonce = wp_create_nonce( 'rain_decide_' . $public );
			$label = 'approve' === $action ? __( 'Approve login', 'rain-admin-login-security' ) : __( 'Deny login', 'rain-admin-login-security' );
			$form  = '<p>' . esc_html__( 'Confirm this security decision. The action will not sign anyone in.', 'rain-admin-login-security' ) . '</p><form method="post">';
			$form .= '<input type="hidden" name="action" value="' . esc_attr( $action ) . '"><input type="hidden" name="request" value="' . esc_attr( $public ) . '"><input type="hidden" name="token" value="' . esc_attr( $token ) . '"><input type="hidden" name="rain_decision_nonce" value="' . esc_attr( $nonce ) . '"><button class="rain-button" type="submit">' . esc_html( $label ) . '</button></form>';
			$this->render_page( __( 'Confirm Web Route decision', 'rain-admin-login-security' ), $form, 200 );
		}
		if ( ! isset( $_POST['rain_decision_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['rain_decision_nonce'] ) ), 'rain_decide_' . $public ) ) {
			$this->render_page( __( 'Decision expired', 'rain-admin-login-security' ), '<p>' . esc_html__( 'Please reopen the approval email and try again.', 'rain-admin-login-security' ) . '</p>', 403 );
		}
		$result = $this->approval->decide_by_token( $public, $token, $action );
		$message = is_wp_error( $result ) ? $result->get_error_message() : ( 'approve' === $action ? __( 'The login request was approved.', 'rain-admin-login-security' ) : __( 'The login request was denied.', 'rain-admin-login-security' ) );
		$this->render_page( __( 'Web Route decision', 'rain-admin-login-security' ), '<p>' . esc_html( $message ) . '</p>', is_wp_error( $result ) ? 403 : 200 );
	}

	private function handle_logout() {
		$nonce = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : '';
		if ( ! is_user_logged_in() || ! wp_verify_nonce( $nonce, 'log-out' ) ) {
			$this->render_page( __( 'Logout unavailable', 'rain-admin-login-security' ), '<p>' . esc_html__( 'The logout link is invalid or expired.', 'rain-admin-login-security' ) . '</p>', 403 );
		}
		wp_logout();
		$redirect = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), home_url( '/' ) ) : home_url( '/' );
		wp_safe_redirect( $redirect );
		exit;
	}

	private function handle_lostpassword() {
		$message = '';
		if ( 'POST' === strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET' ) ) {
			$nonce = isset( $_POST['rain_lost_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['rain_lost_nonce'] ) ) : '';
			if ( ! wp_verify_nonce( $nonce, 'rain_lostpassword' ) ) {
				$message = __( 'The form expired. Please try again.', 'rain-admin-login-security' );
			} else {
				$login = isset( $_POST['user_login'] ) ? sanitize_text_field( wp_unslash( $_POST['user_login'] ) ) : '';
				$result = retrieve_password( $login );
				$message = is_wp_error( $result ) ? __( 'If the account exists, a password reset message will be sent.', 'rain-admin-login-security' ) : __( 'If the account exists, a password reset message will be sent.', 'rain-admin-login-security' );
			}
		}
		$content = $message ? '<p>' . esc_html( $message ) . '</p>' : '';
		$content .= '<form method="post"><label for="rain-user-login">' . esc_html__( 'Username or email', 'rain-admin-login-security' ) . '</label><input id="rain-user-login" name="user_login" type="text" required autocomplete="username"><input type="hidden" name="rain_lost_nonce" value="' . esc_attr( wp_create_nonce( 'rain_lostpassword' ) ) . '"><button class="rain-button" type="submit">' . esc_html__( 'Send reset link', 'rain-admin-login-security' ) . '</button></form>';
		$this->render_page( __( 'Reset password', 'rain-admin-login-security' ), $content, 200 );
	}

	private function handle_register() {
		if ( ! get_option( 'users_can_register' ) ) {
			$this->render_page( __( 'Registration unavailable', 'rain-admin-login-security' ), '<p>' . esc_html__( 'Account registration is managed by the site owner.', 'rain-admin-login-security' ) . '</p>', 403 );
		}
		$message = '';
		if ( 'POST' === strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET' ) ) {
			$nonce = isset( $_POST['rain_register_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['rain_register_nonce'] ) ) : '';
			if ( ! wp_verify_nonce( $nonce, 'rain_register' ) ) {
				$message = __( 'The form expired. Please try again.', 'rain-admin-login-security' );
			} else {
				$login = isset( $_POST['user_login'] ) ? sanitize_user( wp_unslash( $_POST['user_login'] ) ) : '';
				$email = isset( $_POST['user_email'] ) ? sanitize_email( wp_unslash( $_POST['user_email'] ) ) : '';
				$result = register_new_user( $login, $email );
				$message = is_wp_error( $result ) ? $result->get_error_message() : __( 'Registration complete. Check your email for the next step.', 'rain-admin-login-security' );
			}
		}
		$content = $message ? '<div class="rain-error" role="alert">' . esc_html( $message ) . '</div>' : '';
		$content .= '<form method="post"><label for="rain-register-login">' . esc_html__( 'Username', 'rain-admin-login-security' ) . '</label><input id="rain-register-login" name="user_login" type="text" required autocomplete="username"><label for="rain-register-email">' . esc_html__( 'Email', 'rain-admin-login-security' ) . '</label><input id="rain-register-email" name="user_email" type="email" required autocomplete="email"><input type="hidden" name="rain_register_nonce" value="' . esc_attr( wp_create_nonce( 'rain_register' ) ) . '"><button class="rain-button" type="submit">' . esc_html__( 'Register', 'rain-admin-login-security' ) . '</button></form>';
		$this->render_page( __( 'Create an account', 'rain-admin-login-security' ), $content, 200 );
	}

	private function handle_reset_password() {
		$key   = isset( $_REQUEST['key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['key'] ) ) : '';
		$login = isset( $_REQUEST['login'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['login'] ) ) : '';
		$user  = $key && $login ? check_password_reset_key( $key, $login ) : new \WP_Error( 'invalid_key' );
		if ( is_wp_error( $user ) ) {
			$this->render_page( __( 'Reset link invalid', 'rain-admin-login-security' ), '<p>' . esc_html__( 'This password reset link is invalid or has expired.', 'rain-admin-login-security' ) . '</p>', 403 );
		}
		$message = '';
		if ( 'POST' === strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET' ) ) {
			$nonce = isset( $_POST['rain_reset_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['rain_reset_nonce'] ) ) : '';
			$pass1 = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
			$pass2 = isset( $_POST['pass2'] ) ? (string) wp_unslash( $_POST['pass2'] ) : '';
			if ( ! wp_verify_nonce( $nonce, 'rain_reset_' . $user->ID ) ) {
				$message = __( 'The form expired. Please reopen the reset link.', 'rain-admin-login-security' );
			} elseif ( ! $pass1 || $pass1 !== $pass2 ) {
				$message = __( 'The passwords do not match.', 'rain-admin-login-security' );
			} else {
				reset_password( $user, $pass1 );
				$this->render_page( __( 'Password updated', 'rain-admin-login-security' ), '<p>' . esc_html__( 'Your password was updated. You can now sign in through Web Route.', 'rain-admin-login-security' ) . '</p><p><a class="rain-button" href="' . esc_url( $this->config->route_url() ) . '">' . esc_html__( 'Return to Web Route', 'rain-admin-login-security' ) . '</a></p>', 200 );
			}
		}
		$content = $message ? '<p>' . esc_html( $message ) . '</p>' : '';
		$content .= '<form method="post"><label for="rain-pass1">' . esc_html__( 'New password', 'rain-admin-login-security' ) . '</label><input id="rain-pass1" name="pass1" type="password" required autocomplete="new-password"><label for="rain-pass2">' . esc_html__( 'Repeat password', 'rain-admin-login-security' ) . '</label><input id="rain-pass2" name="pass2" type="password" required autocomplete="new-password"><input type="hidden" name="key" value="' . esc_attr( $key ) . '"><input type="hidden" name="login" value="' . esc_attr( $login ) . '"><input type="hidden" name="rain_reset_nonce" value="' . esc_attr( wp_create_nonce( 'rain_reset_' . $user->ID ) ) . '"><button class="rain-button" type="submit">' . esc_html__( 'Update password', 'rain-admin-login-security' ) . '</button></form>';
		$this->render_page( __( 'Choose a new password', 'rain-admin-login-security' ), $content, 200 );
	}

	private function complete_login( \WP_User $user, $remember, $redirect ) {
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, (bool) $remember, is_ssl() );
		do_action( 'wp_login', $user->user_login, $user );
		wp_safe_redirect( wp_validate_redirect( $redirect, admin_url() ) );
		exit;
	}

	private function render_login( $error = '' ) {
		$limit = $this->limiter->status();
		if ( $limit['blocked'] ) {
			$this->render_blocked( $limit );
		}
		$content = $error ? '<div class="rain-error" role="alert">' . esc_html( $error ) . '</div>' : '';
		$content .= '<form method="post" autocomplete="on"><label for="rain-log">' . esc_html__( 'Username or email', 'rain-admin-login-security' ) . '</label><input id="rain-log" name="log" type="text" required autocomplete="username"><label for="rain-pwd">' . esc_html__( 'Password', 'rain-admin-login-security' ) . '</label><input id="rain-pwd" name="pwd" type="password" required autocomplete="current-password"><label class="rain-check"><input name="rememberme" type="checkbox" value="1"> ' . esc_html__( 'Remember me', 'rain-admin-login-security' ) . '</label><input type="hidden" name="rain_nonce" value="' . esc_attr( wp_create_nonce( 'rain_login' ) ) . '"><input type="hidden" name="redirect_to" value="' . esc_attr( isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), admin_url() ) : admin_url() ) . '"><button class="rain-button" type="submit">' . esc_html__( 'Continue securely', 'rain-admin-login-security' ) . '</button></form><p class="rain-links"><a href="' . esc_url( $this->config->route_url( array( 'action' => 'lostpassword' ) ) ) . '">' . esc_html__( 'Forgot password?', 'rain-admin-login-security' ) . '</a></p>';
		$this->render_page( __( 'Secure administrator access', 'rain-admin-login-security' ), $content, 200 );
	}

	private function render_waiting( $public_id, $expires ) {
		$endpoint = $this->config->route_url();
		$content = '<div class="rain-spinner" aria-hidden="true"></div><p>' . esc_html__( 'Your credentials are valid. Waiting for an administrator to approve this login.', 'rain-admin-login-security' ) . '</p><p id="rain-status" class="rain-muted">' . esc_html__( 'This page checks securely for approval.', 'rain-admin-login-security' ) . '</p><noscript><p>' . esc_html__( 'JavaScript is disabled. Refresh this page after approval.', 'rain-admin-login-security' ) . '</p></noscript><script>(function(){var endpoint=' . wp_json_encode( $endpoint ) . ',request=' . wp_json_encode( $public_id ) . ',expires=' . (int) $expires . ',status=document.getElementById("rain-status");function post(action){var data=new URLSearchParams({action:action,request:request});return fetch(endpoint,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:data}).then(function(r){return r.json();});}function poll(){if(Date.now()/1000>expires){status.textContent=' . wp_json_encode( __( 'This request expired. Please start again.', 'rain-admin-login-security' ) ) . ';return;}post("status").then(function(r){var s=r&&r.data&&r.data.status;if("approved"===s){status.textContent=' . wp_json_encode( __( 'Approved. Signing you in…', 'rain-admin-login-security' ) ) . ';return post("exchange");}if("denied"===s){status.textContent=' . wp_json_encode( __( 'The request was denied.', 'rain-admin-login-security' ) ) . ';return;}if("expired"===s||"invalid"===s){status.textContent=' . wp_json_encode( __( 'This request is no longer valid. Please start again.', 'rain-admin-login-security' ) ) . ';return;}setTimeout(poll,2500);}).then(function(r){if(r&&r.success===false){status.textContent=' . wp_json_encode( __( 'This approval is no longer valid. Please start again.', 'rain-admin-login-security' ) ) . ';}else if(r&&r.success&&r.data&&r.data.redirect){window.location.href=r.data.redirect;}}).catch(function(){setTimeout(poll,5000);});}poll();})();</script>';
		$this->render_page( __( 'Approval requested', 'rain-admin-login-security' ), $content, 200 );
	}

	private function render_blocked( array $limit ) {
		$minutes = max( 1, (int) ceil( $limit['remaining'] / 60 ) );
		$content = '<div class="rain-block-icon" aria-hidden="true">!</div><p>' . sprintf( esc_html__( 'This IP address has been blocked by %s after too many failed login attempts.', 'rain-admin-login-security' ), esc_html( get_bloginfo( 'name' ) ) ) . '</p><p class="rain-ip">' . esc_html__( 'Your IP:', 'rain-admin-login-security' ) . ' <strong>' . esc_html( $limit['ip'] ) . '</strong></p><p class="rain-muted">' . sprintf( esc_html__( 'Try again in approximately %d minute(s).', 'rain-admin-login-security' ), $minutes ) . '</p>';
		$this->render_page( __( 'Access temporarily blocked', 'rain-admin-login-security' ), $content, 429, array( 'Retry-After' => (string) max( 1, (int) $limit['remaining'] ) ) );
	}

	private function render_decoy( $status = 404 ) {
		$content = '<div class="rain-decoy-mark" aria-hidden="true"></div><h1>' . esc_html__( 'This is not a WordPress website', 'rain-admin-login-security' ) . '</h1><p>' . esc_html__( 'The page you requested could not be found.', 'rain-admin-login-security' ) . '</p>';
		$this->render_page( __( 'Page not found', 'rain-admin-login-security' ), $content, $status );
	}

	private function render_page( $title, $content, $status = 200, array $headers = array() ) {
		nocache_headers();
		status_header( $status );
		if ( function_exists( 'header_remove' ) ) {
			header_remove( 'X-Powered-By' );
		}
		header( 'X-Robots-Tag: noindex, nofollow, noarchive' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Referrer-Policy: no-referrer' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
		header( "Content-Security-Policy: default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'" );
		foreach ( $headers as $name => $value ) {
			header( $name . ': ' . $value );
		}
		$site = get_bloginfo( 'name' );
		?><!doctype html><html lang="<?php echo esc_attr( determine_locale() ); ?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?php echo esc_html( $title . ' — ' . $site ); ?></title><style><?php echo $this->styles(); ?></style></head><body><main class="rain-shell"><div class="rain-orb rain-orb-a"></div><div class="rain-orb rain-orb-b"></div><section class="rain-card"><div class="rain-brand" aria-label="Web Route">W</div><p class="rain-kicker">WEB ROUTE SECURITY</p><h1><?php echo esc_html( $title ); ?></h1><?php echo $content; ?></section></main></body></html><?php
		exit;
	}

	private function styles() {
		return '.rain-shell{min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box;background:linear-gradient(145deg,#f8fbff,#dbeeff);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#102a43;overflow:hidden;position:relative}.rain-card{position:relative;z-index:2;width:min(100%,460px);box-sizing:border-box;padding:42px;border:1px solid rgba(255,255,255,.8);border-radius:28px;background:rgba(255,255,255,.84);box-shadow:0 24px 80px rgba(28,91,145,.18);backdrop-filter:blur(14px);text-align:center;animation:rain-in .7s ease both}.rain-brand{width:52px;height:52px;display:grid;place-items:center;margin:0 auto 14px;border-radius:16px;background:#1261a0;color:#fff;font-weight:800;font-size:28px;box-shadow:0 10px 22px rgba(18,97,160,.28)}.rain-kicker{margin:0 0 10px;color:#2574a9;letter-spacing:.18em;font-size:11px;font-weight:800}.rain-card h1{margin:0 0 18px;font-size:clamp(25px,5vw,34px);line-height:1.12;color:#0b2540}.rain-card p{line-height:1.65}.rain-card form{display:grid;gap:10px;text-align:left;margin-top:22px}.rain-card label{font-size:13px;font-weight:700;color:#244b6b}.rain-card input[type=text],.rain-card input[type=password]{width:100%;box-sizing:border-box;padding:13px 14px;border:1px solid #b7d0e5;border-radius:12px;background:#fff;color:#102a43;font:inherit}.rain-card input:focus{outline:3px solid rgba(32,137,213,.25);border-color:#2089d5}.rain-check{display:flex;align-items:center;gap:8px;font-weight:500!important}.rain-check input{accent-color:#1261a0}.rain-button{display:inline-block;border:0;border-radius:12px;padding:13px 18px;background:#1261a0;color:#fff;text-align:center;text-decoration:none;font:700 15px inherit;cursor:pointer;box-shadow:0 10px 20px rgba(18,97,160,.22)}.rain-button:hover{background:#0b4f86}.rain-error{padding:11px 13px;border-radius:10px;background:#fff0f1;color:#a22635;font-size:14px}.rain-links{font-size:13px}.rain-links a{color:#1261a0}.rain-muted{color:#54718b;font-size:14px}.rain-ip{font-size:16px;word-break:break-all}.rain-spinner{width:52px;height:52px;margin:4px auto 22px;border:5px solid #c2dcf1;border-top-color:#1261a0;border-radius:50%;animation:rain-spin 1s linear infinite}.rain-block-icon{width:58px;height:58px;display:grid;place-items:center;margin:4px auto 20px;border-radius:50%;background:#1261a0;color:#fff;font-size:34px;font-weight:800;animation:rain-pulse 1.8s ease-in-out infinite}.rain-decoy-mark{width:70px;height:70px;margin:0 auto 20px;border:5px solid #b7d8f3;border-radius:50%;box-shadow:inset 0 0 0 12px #eaf5ff;animation:rain-pulse 2.4s ease-in-out infinite}.rain-orb{position:absolute;border-radius:50%;filter:blur(1px);opacity:.55;background:linear-gradient(135deg,#5db7f2,#a7ddff);animation:rain-float 8s ease-in-out infinite}.rain-orb-a{width:240px;height:240px;top:-80px;left:-70px}.rain-orb-b{width:320px;height:320px;right:-100px;bottom:-130px;animation-delay:-3s}@keyframes rain-in{from{opacity:0;transform:translateY(16px) scale(.98)}to{opacity:1;transform:none}}@keyframes rain-spin{to{transform:rotate(360deg)}}@keyframes rain-pulse{0%,100%{transform:scale(1);opacity:.85}50%{transform:scale(1.06);opacity:1}}@keyframes rain-float{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(15px,24px,0)}}@media (max-width:520px){.rain-card{padding:30px 22px;border-radius:22px}}@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.001ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}';
	}

	private function set_verifier_cookie( $verifier ) {
		$path = defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/';
		setcookie( 'rain_request_verifier', $verifier, array( 'expires' => time() + (int) $this->config->get( 'request_ttl', 600 ), 'path' => $path, 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Strict' ) );
	}

	private function get_verifier() {
		return isset( $_COOKIE['rain_request_verifier'] ) ? preg_replace( '/[^a-f0-9]/', '', strtolower( wp_unslash( $_COOKIE['rain_request_verifier'] ) ) ) : '';
	}

	private function clear_verifier_cookie() {
		$path = defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/';
		setcookie( 'rain_request_verifier', '', array( 'expires' => time() - HOUR_IN_SECONDS, 'path' => $path, 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Strict' ) );
		unset( $_COOKIE['rain_request_verifier'] );
	}

	private function is_rain_request() {
		if ( get_query_var( 'rain_security' ) ) {
			return true;
		}
		$path = trim( $this->request_path(), '/' );
		$route = trim( wp_parse_url( $this->config->route_url(), PHP_URL_PATH ), '/' );
		return $path === $route || ( substr( $path, -strlen( $route ) ) === $route && preg_match( '#/(?:' . preg_quote( $route, '#' ) . ')$#i', $path ) );
	}

	private function request_contains( $fragment ) {
		return false !== stripos( $this->request_path(), $fragment );
	}

	private function request_path() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		return is_string( $path ) ? $path : '/';
	}
}
