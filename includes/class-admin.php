<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Admin {
	private $config;
	private $repository;
	private $approval;
	private $limiter;
	private $ip;

	public function __construct( Config $config, Request_Repository $repository, Approval_Service $approval, Rate_Limiter $limiter, Client_IP $ip ) {
		$this->config     = $config;
		$this->repository = $repository;
		$this->approval   = $approval;
		$this->limiter    = $limiter;
		$this->ip         = $ip;
	}

	public function register_hooks() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'network_admin_menu', array( $this, 'network_menu' ) );
		add_action( 'admin_post_rain_save_settings', array( $this, 'save_settings' ) );
		add_action( 'admin_post_rain_decide_request', array( $this, 'decide_request' ) );
		add_action( 'admin_post_rain_test_email', array( $this, 'test_email' ) );
		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	public function menu() {
		add_options_page( __( 'Web Route', 'rain-admin-login-security' ), __( 'Web Route', 'rain-admin-login-security' ), 'manage_options', 'rain-security', array( $this, 'render' ) );
	}

	public function network_menu() {
		if ( is_multisite() ) {
			add_submenu_page( 'settings.php', __( 'Web Route', 'rain-admin-login-security' ), __( 'Web Route', 'rain-admin-login-security' ), 'manage_network_options', 'rain-security', array( $this, 'render' ) );
		}
	}

	public function save_settings() {
		if ( ! $this->can_manage() || ! isset( $_POST['rain_settings_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['rain_settings_nonce'] ) ), 'rain_save_settings' ) ) {
			wp_die( esc_html__( 'You are not allowed to change Web Route settings.', 'rain-admin-login-security' ), 403 );
		}
		$input = isset( $_POST['rain'] ) && is_array( $_POST['rain'] ) ? $_POST['rain'] : array();
		$settings = $this->config->sanitized_settings( $input );
		$eligible = array_values( array_filter( $settings['approver_ids'], array( $this->config, 'is_eligible_approver_id' ) ) );
		$settings['approver_ids'] = $eligible;
		if ( $settings['enabled'] && ! is_ssl() ) {
			$this->redirect( 'no_https' );
		}
		if ( $settings['enabled'] && ! $eligible ) {
			$settings['enabled'] = 0;
			$this->redirect( 'no_approver' );
		}
		if ( $settings['enabled'] && empty( $settings['email_tested_at'] ) ) {
			$settings['enabled'] = 0;
			$this->redirect( 'email_not_tested' );
		}
		$old_route = $this->config->route();
		$old_approvers = $this->config->approver_ids();
		if ( $old_approvers !== $eligible ) {
			$settings['email_tested_at'] = 0;
		}
		if ( isset( $_FILES['rain_brand_image'] ) && is_array( $_FILES['rain_brand_image'] ) && UPLOAD_ERR_NO_FILE !== (int) $_FILES['rain_brand_image']['error'] ) {
			if ( UPLOAD_ERR_OK !== (int) $_FILES['rain_brand_image']['error'] || ! current_user_can( 'upload_files' ) ) {
				$this->redirect( 'image_upload_failed' );
			}

			require_once ABSPATH . 'wp-admin/includes/file.php';
			require_once ABSPATH . 'wp-admin/includes/image.php';
			require_once ABSPATH . 'wp-admin/includes/media.php';

			$attachment_id = media_handle_upload( 'rain_brand_image', 0, array(), array( 'test_form' => false ) );
			if ( is_wp_error( $attachment_id ) ) {
				$this->redirect( 'image_upload_failed' );
			}

			$settings['brand_image_id'] = absint( $attachment_id );
		}
		$this->config->update( $settings );
		if ( $old_route !== $this->config->route() ) {
			add_rewrite_rule( '^' . preg_quote( $this->config->route(), '#' ) . '/?$', 'index.php?rain_security=1', 'top' );
			flush_rewrite_rules();
		}
		$this->redirect( 'saved' );
	}

	public function decide_request() {
		if ( ! $this->can_approve() || ! isset( $_POST['rain_admin_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['rain_admin_nonce'] ) ), 'rain_admin_decide' ) ) {
			wp_die( esc_html__( 'You are not allowed to decide Web Route requests.', 'rain-admin-login-security' ), 403 );
		}
		$public = isset( $_POST['request'] ) ? sanitize_text_field( wp_unslash( $_POST['request'] ) ) : '';
		$action = isset( $_POST['decision'] ) ? sanitize_key( wp_unslash( $_POST['decision'] ) ) : 'deny';
		$result = $this->approval->decide_by_user( $public, get_current_user_id(), $action );
		$this->redirect( is_wp_error( $result ) ? 'decision_error' : 'decision_saved' );
	}

	public function test_email() {
		if ( ! $this->can_manage() || ! isset( $_POST['rain_email_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['rain_email_nonce'] ) ), 'rain_test_email' ) ) {
			wp_die( esc_html__( 'You are not allowed to send a Web Route test email.', 'rain-admin-login-security' ), 403 );
		}
		$recipients = array();
		foreach ( $this->config->approver_ids() as $approver_id ) {
			$approver = get_user_by( 'id', $approver_id );
			if ( $approver && is_email( $approver->user_email ) ) {
				$recipients[] = $approver->user_email;
			}
		}
		$recipients = $recipients ? array_values( array_unique( $recipients ) ) : get_option( 'admin_email' );
		$sent = wp_mail( $recipients, __( 'Web Route test email', 'rain-admin-login-security' ), __( 'Web Route email delivery is working. Do not reply to this message.', 'rain-admin-login-security' ) );
		if ( $sent ) {
			$settings = $this->config->all();
			$settings['email_tested_at'] = time();
			$this->config->update( $settings );
		}
		$this->redirect( $sent ? 'email_sent' : 'email_failed' );
	}

	public function notice() {
		if ( ! $this->can_manage() || ! $this->config->is_enabled() ) {
			return;
		}
		$pending = $this->approval->pending( 1 );
		if ( $pending ) {
			echo '<div class="notice notice-warning"><p><a href="' . esc_url( $this->page_url() . '#rain-requests' ) . '">' . esc_html__( 'Web Route has a pending administrator login approval request.', 'rain-admin-login-security' ) . '</a></p></div>';
		}
	}

	public function render() {
		if ( ! $this->can_manage() ) {
			wp_die( esc_html__( 'You are not allowed to view Web Route settings.', 'rain-admin-login-security' ), 403 );
		}
		$settings        = $this->config->all();
		$users           = get_users( array( 'capability' => is_multisite() ? 'manage_network_options' : 'manage_options', 'fields' => array( 'ID', 'display_name', 'user_email' ) ) );
		$requests        = $this->approval->pending( 50 );
		$notice          = isset( $_GET['rain_notice'] ) ? sanitize_key( wp_unslash( $_GET['rain_notice'] ) ) : '';
		$brand_image_url = absint( $settings['brand_image_id'] ) ? wp_get_attachment_image_url( absint( $settings['brand_image_id'] ), 'thumbnail' ) : '';
		$brand_color     = $this->config->brand_color();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Web Route', 'rain-admin-login-security' ); ?></h1>
			<?php $this->render_notice( $notice ); ?>
			<p><?php esc_html_e( 'Web Route protects privileged browser logins with password verification followed by administrator approval.', 'rain-admin-login-security' ); ?></p>
			<p><strong><?php esc_html_e( 'Login URL:', 'rain-admin-login-security' ); ?></strong> <code><?php echo esc_html( $this->config->route_url() ); ?></code></p>
			<form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="rain_save_settings">
				<?php wp_nonce_field( 'rain_save_settings', 'rain_settings_nonce' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="rain-enabled"><?php esc_html_e( 'Enable protection', 'rain-admin-login-security' ); ?></label></th>
						<td><label><input id="rain-enabled" name="rain[enabled]" type="checkbox" value="1" <?php checked( $settings['enabled'], 1 ); ?>> <?php esc_html_e( 'Require approval for protected logins', 'rain-admin-login-security' ); ?></label><p class="description"><?php esc_html_e( 'Before enabling, confirm that email delivery and the recovery method work.', 'rain-admin-login-security' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><label for="rain-route"><?php esc_html_e( 'Web Route slug', 'rain-admin-login-security' ); ?></label></th>
						<td><input id="rain-route" class="regular-text" name="rain[route]" value="<?php echo esc_attr( $settings['route'] ); ?>" maxlength="48"><p class="description"><?php esc_html_e( 'Use a memorable route such as web-route. This is not a substitute for authentication.', 'rain-admin-login-security' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><label for="rain-brand-image-id"><?php esc_html_e( 'Security page image', 'rain-admin-login-security' ); ?></label></th>
						<td>
							<input id="rain-brand-image-id" name="rain[brand_image_id]" type="hidden" value="<?php echo absint( $settings['brand_image_id'] ); ?>">
							<img id="rain-brand-preview" src="<?php echo esc_url( $brand_image_url ); ?>" alt="" style="display:<?php echo $brand_image_url ? 'block' : 'none'; ?>;width:96px;height:96px;object-fit:contain;margin:0 0 12px;padding:8px;border:1px solid #c3c4c7;border-radius:8px;background:#fff;">
							<input id="rain-brand-file" name="rain_brand_image" type="file" accept="image/*" class="screen-reader-text">
							<label for="rain-brand-file" class="button"><?php esc_html_e( 'Choose image', 'rain-admin-login-security' ); ?></label>
							<button id="rain-remove-brand" type="button" class="button" style="display:<?php echo $brand_image_url ? 'inline-block' : 'none'; ?>"><?php esc_html_e( 'Remove image', 'rain-admin-login-security' ); ?></button>
							<p class="description"><?php esc_html_e( 'Choose an image from your computer, then save the settings. It replaces the W on this website’s security pages and is used as the 404 watermark. Transparent PNG, WebP, and wide logo images work well.', 'rain-admin-login-security' ); ?></p>
							<p style="display:flex;align-items:center;gap:10px;margin-top:12px;">
								<label for="rain-brand-color"><strong><?php esc_html_e( 'Logo theme color', 'rain-admin-login-security' ); ?></strong></label>
								<input id="rain-brand-color" name="rain[brand_color]" type="color" value="<?php echo esc_attr( $brand_color ); ?>">
								<code id="rain-brand-color-value"><?php echo esc_html( $brand_color ); ?></code>
							</p>
							<p class="description"><?php esc_html_e( 'Automatically matched to the selected logo. You can adjust it before saving.', 'rain-admin-login-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Approvers', 'rain-admin-login-security' ); ?></th>
						<td>
							<?php foreach ( $users as $user ) : ?>
								<label style="display:block;margin:4px 0"><input type="checkbox" name="rain[approver_ids][]" value="<?php echo (int) $user->ID; ?>" <?php checked( in_array( (int) $user->ID, $this->config->approver_ids(), true ), true ); ?>> <?php echo esc_html( $user->display_name . ' (' . $user->user_email . ')' ); ?></label>
							<?php endforeach; ?>
							<p class="description"><?php esc_html_e( 'Approvers receive email notifications and can decide in this dashboard.', 'rain-admin-login-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="rain-ttl"><?php esc_html_e( 'Approval lifetime (seconds)', 'rain-admin-login-security' ); ?></label></th>
						<td><input id="rain-ttl" type="number" min="120" max="3600" name="rain[request_ttl]" value="<?php echo (int) $settings['request_ttl']; ?>"></td>
					</tr>
					<tr>
						<th scope="row"><label for="rain-proxy-header"><?php esc_html_e( 'Trusted proxy header', 'rain-admin-login-security' ); ?></label></th>
						<td><select id="rain-proxy-header" name="rain[trusted_proxy_header]"><option value=""><?php esc_html_e( 'None (use REMOTE_ADDR)', 'rain-admin-login-security' ); ?></option><?php foreach ( array( 'HTTP_CF_CONNECTING_IP' => 'Cloudflare', 'HTTP_X_FORWARDED_FOR' => 'X-Forwarded-For', 'HTTP_X_REAL_IP' => 'X-Real-IP' ) as $value => $label ) : ?><option value="<?php echo esc_attr( $value ); ?>" <?php selected( $settings['trusted_proxy_header'], $value ); ?>><?php echo esc_html( $label ); ?></option><?php endforeach; ?></select><p class="description"><?php esc_html_e( 'Only used when the connecting address matches a trusted proxy CIDR below.', 'rain-admin-login-security' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><label for="rain-proxy-cidrs"><?php esc_html_e( 'Trusted proxy CIDRs', 'rain-admin-login-security' ); ?></label></th>
						<td><textarea id="rain-proxy-cidrs" name="rain[trusted_proxy_cidrs]" rows="4" class="large-text code"><?php echo esc_textarea( $settings['trusted_proxy_cidrs'] ); ?></textarea></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Protection and privacy', 'rain-admin-login-security' ); ?></th>
						<td>
							<label style="display:block"><input type="checkbox" name="rain[bind_request_ip]" value="1" <?php checked( $settings['bind_request_ip'], 1 ); ?>> <?php esc_html_e( 'Bind approval to the originating IP', 'rain-admin-login-security' ); ?></label>
							<label style="display:block"><input type="checkbox" name="rain[restrict_rest_users]" value="1" <?php checked( $settings['restrict_rest_users'], 1 ); ?>> <?php esc_html_e( 'Restrict anonymous REST user enumeration', 'rain-admin-login-security' ); ?></label>
							<label style="display:block"><input type="checkbox" name="rain[hide_discovery_links]" value="1" <?php checked( $settings['hide_discovery_links'], 1 ); ?>> <?php esc_html_e( 'Remove discovery/version links', 'rain-admin-login-security' ); ?></label>
							<label style="display:block"><input type="checkbox" name="rain[block_author_enum]" value="1" <?php checked( $settings['block_author_enum'], 1 ); ?>> <?php esc_html_e( 'Reduce author enumeration', 'rain-admin-login-security' ); ?></label>
							<label style="display:block"><input type="checkbox" name="rain[disable_xmlrpc_auth]" value="1" <?php checked( $settings['disable_xmlrpc_auth'], 1 ); ?>> <?php esc_html_e( 'Block protected authentication through XML-RPC', 'rain-admin-login-security' ); ?></label>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save Web Route settings', 'rain-admin-login-security' ) ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block">
				<input type="hidden" name="action" value="rain_test_email">
				<?php wp_nonce_field( 'rain_test_email', 'rain_email_nonce' ); ?>
				<?php submit_button( __( 'Send test email', 'rain-admin-login-security' ), 'secondary', 'submit', false ); ?>
			</form>
			<h2 id="rain-requests"><?php esc_html_e( 'Pending approvals', 'rain-admin-login-security' ); ?></h2>
			<?php if ( ! $requests ) : ?>
				<p><?php esc_html_e( 'No pending requests.', 'rain-admin-login-security' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th><?php esc_html_e( 'Account', 'rain-admin-login-security' ); ?></th><th><?php esc_html_e( 'IP', 'rain-admin-login-security' ); ?></th><th><?php esc_html_e( 'Browser', 'rain-admin-login-security' ); ?></th><th><?php esc_html_e( 'Expires', 'rain-admin-login-security' ); ?></th><th><?php esc_html_e( 'Decision', 'rain-admin-login-security' ); ?></th></tr></thead>
					<tbody>
						<?php foreach ( $requests as $request ) : $user = get_user_by( 'id', $request->user_id ); ?>
							<tr><td><?php echo esc_html( $user ? $user->user_login : __( 'Deleted user', 'rain-admin-login-security' ) ); ?></td><td><?php echo esc_html( $request->ip_display ); ?></td><td><?php echo esc_html( $request->browser_summary ); ?></td><td><?php echo esc_html( $request->expires_at ); ?> UTC</td><td><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline"><input type="hidden" name="action" value="rain_decide_request"><input type="hidden" name="request" value="<?php echo esc_attr( $request->public_id ); ?>"><input type="hidden" name="decision" value="approve"><?php wp_nonce_field( 'rain_admin_decide', 'rain_admin_nonce' ); ?><button class="button button-primary"><?php esc_html_e( 'Approve', 'rain-admin-login-security' ); ?></button></form> <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline"><input type="hidden" name="action" value="rain_decide_request"><input type="hidden" name="request" value="<?php echo esc_attr( $request->public_id ); ?>"><input type="hidden" name="decision" value="deny"><?php wp_nonce_field( 'rain_admin_decide', 'rain_admin_nonce' ); ?><button class="button"><?php esc_html_e( 'Deny', 'rain-admin-login-security' ); ?></button></form></td></tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<script>
		(function () {
			var fileInput = document.getElementById('rain-brand-file');
			var removeButton = document.getElementById('rain-remove-brand');
			var imageId = document.getElementById('rain-brand-image-id');
			var preview = document.getElementById('rain-brand-preview');
			var colorInput = document.getElementById('rain-brand-color');
			var colorValue = document.getElementById('rain-brand-color-value');
			var defaultColor = '#49cad8';
			var localPreviewUrl = '';

			function setColor(color) {
				if (!/^#[0-9a-f]{6}$/i.test(color)) {
					return;
				}
				colorInput.value = color.toLowerCase();
				colorValue.textContent = colorInput.value;
			}

			function detectColor(source) {
				var sample = new Image();
				if (source.indexOf('blob:') !== 0 && source.indexOf('data:') !== 0) {
					sample.crossOrigin = 'anonymous';
				}
				sample.onload = function () {
					var canvas = document.createElement('canvas');
					var context;
					var pixels;
					var buckets = {};
					var best = null;
					var x;

					canvas.width = 48;
					canvas.height = 48;
					context = canvas.getContext('2d', { willReadFrequently: true });
					if (!context) {
						return;
					}

					try {
						context.drawImage(sample, 0, 0, canvas.width, canvas.height);
						pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
					} catch (error) {
						return;
					}

					for (x = 0; x < pixels.length; x += 4) {
						var red = pixels[x];
						var green = pixels[x + 1];
						var blue = pixels[x + 2];
						var alpha = pixels[x + 3] / 255;
						var maximum = Math.max(red, green, blue);
						var minimum = Math.min(red, green, blue);
						var saturation = maximum ? (maximum - minimum) / maximum : 0;
						var luminance = (0.2126 * red + 0.7152 * green + 0.0722 * blue) / 255;
						var key;

						if (alpha < 0.5 || saturation < 0.18 || luminance < 0.08 || luminance > 0.94) {
							continue;
						}

						key = (red >> 4) + '-' + (green >> 4) + '-' + (blue >> 4);
						if (!buckets[key]) {
							buckets[key] = { red: 0, green: 0, blue: 0, count: 0, score: 0 };
						}
						buckets[key].red += red;
						buckets[key].green += green;
						buckets[key].blue += blue;
						buckets[key].count += 1;
						buckets[key].score += alpha * (0.35 + saturation);
					}

					Object.keys(buckets).forEach(function (key) {
						if (!best || buckets[key].score > best.score) {
							best = buckets[key];
						}
					});

					if (best) {
						var component = function (value) {
							return Math.round(value / best.count).toString(16).padStart(2, '0');
						};
						setColor('#' + component(best.red) + component(best.green) + component(best.blue));
					}
				};
				sample.src = source;
			}

			if (!fileInput || !removeButton || !imageId || !preview || !colorInput || !colorValue) {
				return;
			}

			fileInput.addEventListener('change', function () {
				var file = fileInput.files && fileInput.files[0];
				if (!file || (file.type && file.type.indexOf('image/') !== 0)) {
					return;
				}

				if (localPreviewUrl) {
					URL.revokeObjectURL(localPreviewUrl);
				}
				localPreviewUrl = URL.createObjectURL(file);
				preview.src = localPreviewUrl;
				preview.style.display = 'block';
				removeButton.style.display = 'inline-block';
				detectColor(localPreviewUrl);
			});

			removeButton.addEventListener('click', function () {
				if (localPreviewUrl) {
					URL.revokeObjectURL(localPreviewUrl);
					localPreviewUrl = '';
				}
				fileInput.value = '';
				imageId.value = '';
				preview.removeAttribute('src');
				preview.style.display = 'none';
				removeButton.style.display = 'none';
				setColor(defaultColor);
			});

			colorInput.addEventListener('input', function () {
				setColor(colorInput.value);
			});
		}());
		</script>
		<?php
	}

	private function render_notice( $notice ) {
	$messages = array( 'saved' => array( 'success', __( 'Web Route settings saved.', 'rain-admin-login-security' ) ), 'no_https' => array( 'error', __( 'Web Route protection requires HTTPS. Enable TLS before enforcing protected login.', 'rain-admin-login-security' ) ), 'no_approver' => array( 'error', __( 'Protection was not enabled because no eligible approver was selected.', 'rain-admin-login-security' ) ), 'email_not_tested' => array( 'error', __( 'Send and verify the Web Route test email before enabling protection.', 'rain-admin-login-security' ) ), 'image_upload_failed' => array( 'error', __( 'The security page image could not be uploaded. Choose a supported image file within the site upload limit.', 'rain-admin-login-security' ) ), 'decision_saved' => array( 'success', __( 'Web Route decision saved.', 'rain-admin-login-security' ) ), 'decision_error' => array( 'error', __( 'The request could not be decided; it may have expired or already been handled.', 'rain-admin-login-security' ) ), 'email_sent' => array( 'success', __( 'A test email was sent to the site admin address.', 'rain-admin-login-security' ) ), 'email_failed' => array( 'error', __( 'The test email could not be sent. Configure WordPress mail delivery before enabling Web Route.', 'rain-admin-login-security' ) ) );
	if ( isset( $messages[ $notice ] ) ) {
		echo '<div class="notice notice-' . esc_attr( $messages[ $notice ][0] ) . '"><p>' . esc_html( $messages[ $notice ][1] ) . '</p></div>';
	}
	}

	private function redirect( $notice ) {
		wp_safe_redirect( add_query_arg( 'rain_notice', sanitize_key( $notice ), $this->page_url() ) );
		exit;
	}

	private function page_url() {
		return is_multisite() ? network_admin_url( 'settings.php?page=rain-security' ) : admin_url( 'options-general.php?page=rain-security' );
	}

	private function can_manage() {
		return is_multisite() ? current_user_can( 'manage_network_options' ) : current_user_can( 'manage_options' );
	}

	private function can_approve() {
		return $this->config->can_current_user_approve() && $this->can_manage();
	}
}
