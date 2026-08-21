<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

final class CLI {
	private $config;
	private $repository;
	private $limiter;

	public function __construct( Config $config, Request_Repository $repository, Rate_Limiter $limiter ) {
		$this->config     = $config;
		$this->repository = $repository;
		$this->limiter    = $limiter;
	}

	public function register_hooks() {
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( 'WP_CLI' ) ) {
		\WP_CLI::add_command( 'rain-security', array( $this, 'command' ) );
		}
	}

	/**
	 * Usage: wp rain-security <status|enable|disable|expire|purge>
	 */
	public function command( $args, $assoc_args ) {
		$subcommand = isset( $args[0] ) ? sanitize_key( $args[0] ) : 'status';
		switch ( $subcommand ) {
			case 'status':
				\WP_CLI::log( 'Enabled: ' . ( $this->config->is_enabled() ? 'yes' : 'no' ) );
				\WP_CLI::log( 'Route: ' . $this->config->route_url() );
				\WP_CLI::log( 'Approvers: ' . count( $this->config->approver_ids() ) );
				break;
			case 'enable':
				if ( ! $this->config->approver_ids() ) {
					\WP_CLI::error( 'Select at least one eligible approver first.' );
				}
				if ( 'https' !== strtolower( (string) wp_parse_url( home_url(), PHP_URL_SCHEME ) ) ) {
					\WP_CLI::error( 'Configure the site URL with HTTPS before enabling protection.' );
				}
				if ( ! $this->config->get( 'email_tested_at', 0 ) ) {
					\WP_CLI::error( 'Send a successful Web Route test email before enabling protection.' );
				}
				$settings = $this->config->all();
				$settings['enabled'] = 1;
				$this->config->update( $settings );
				\WP_CLI::success( 'Web Route protection enabled.' );
				break;
			case 'disable':
				$settings = $this->config->all();
				$settings['enabled'] = 0;
				$this->config->update( $settings );
				\WP_CLI::success( 'Web Route protection disabled.' );
				break;
			case 'expire':
				$this->repository->expire();
				$this->limiter->purge_expired();
				\WP_CLI::success( 'Expired Web Route records cleaned.' );
				break;
			case 'purge':
				$days = isset( $assoc_args['days'] ) ? absint( $assoc_args['days'] ) : $this->config->get( 'audit_retention_days', 30 );
				$result = $this->repository->purge( $days );
				\WP_CLI::success( sprintf( 'Purged %d requests and %d audit events.', $result['requests'], $result['events'] ) );
				break;
			default:
				\WP_CLI::error( 'Unknown subcommand. Use status, enable, disable, expire, or purge.' );
		}
	}
}
