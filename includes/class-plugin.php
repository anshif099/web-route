<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class Plugin {
	private static $instance;
	private $config;
	private $router;
	private $admin;
	private $hardening;
	private $cli;

	public static function instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {
		$this->config = new Config();
		$ip           = new Client_IP( $this->config );
		$limiter      = new Rate_Limiter( $this->config, $ip );
		$repository   = new Request_Repository( $this->config );
		$approval     = new Approval_Service( $this->config, $repository, $ip );
		$this->router = new Router( $this->config, $ip, $limiter, $repository, $approval );
		$this->admin  = new Admin( $this->config, $repository, $approval, $limiter, $ip );
		$this->hardening = new Hardening( $this->config );
		$this->cli       = new CLI( $this->config, $repository, $limiter );
	}

	public function register_hooks() {
		add_action( 'plugins_loaded', array( 'Rain\\Security\\Installer', 'maybe_upgrade' ), 1 );
		$this->router->register_hooks();
		$this->admin->register_hooks();
		$this->hardening->register_hooks();
		$this->cli->register_hooks();
	}
}

