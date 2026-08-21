<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$settings = get_option( 'rain_security_settings', array() );
if ( empty( $settings['remove_on_uninstall'] ) ) {
	if ( is_multisite() ) {
		$settings = get_site_option( 'rain_security_settings', array() );
		if ( ! empty( $settings['remove_on_uninstall'] ) ) {
			delete_site_option( 'rain_security_settings' );
			delete_site_option( 'rain_security_db_version' );
		}
	} 
	exit;
}

global $wpdb;
$prefix = is_multisite() ? $wpdb->base_prefix : $wpdb->prefix;
foreach ( array( 'login_requests', 'rate_limits', 'audit_events' ) as $table ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$prefix}rain_{$table}" );
}

if ( is_multisite() ) {
	delete_site_option( 'rain_security_settings' );
	delete_site_option( 'rain_security_db_version' );
} else {
	delete_option( 'rain_security_settings' );
	delete_option( 'rain_security_db_version' );
}
