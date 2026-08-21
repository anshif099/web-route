<?php
namespace Rain\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves the client address without trusting spoofable proxy headers.
 */
final class Client_IP {
	private $config;

	public function __construct( Config $config ) {
		$this->config = $config;
	}

	public function current() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? $this->valid_address( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( ! $remote ) {
			$remote = '0.0.0.0';
		}

		$header = (string) $this->config->get( 'trusted_proxy_header', '' );
		$trusted = $this->trusted_proxy( $remote );
		$address = $remote;
		$source  = 'REMOTE_ADDR';

		if ( $trusted && $header && isset( $_SERVER[ $header ] ) ) {
			$values = explode( ',', (string) wp_unslash( $_SERVER[ $header ] ) );
			$values = array_values( array_filter( array_map( array( $this, 'valid_address' ), $values ) ) );

			if ( 'HTTP_X_FORWARDED_FOR' === $header ) {
				// Walk from the trusted edge toward the client and stop at the first
				// address that is not in the configured proxy set.
				$chain = array_reverse( $values );
				foreach ( $chain as $candidate ) {
					if ( ! $this->trusted_proxy( $candidate ) ) {
						$address = $candidate;
						$source  = $header;
						break;
					}
				}
			} elseif ( ! empty( $values[0] ) ) {
				$address = $values[0];
				$source  = $header;
			}
		}

		return array(
			'address' => $address,
			'hash'    => hash_hmac( 'sha256', $address, wp_salt( 'auth' ) ),
			'source'  => $source,
		);
	}

	public function hash() {
		$current = $this->current();
		return $current['hash'];
	}

	public function is_trusted_proxy( $address ) {
		return $this->trusted_proxy( $address );
	}

	private function valid_address( $address ) {
		$address = trim( (string) $address );
		return filter_var( $address, FILTER_VALIDATE_IP ) ? $address : '';
	}

	private function trusted_proxy( $address ) {
		$address = $this->valid_address( $address );
		if ( ! $address ) {
			return false;
		}

		$cidrs = preg_split( '/\r\n|\r|\n/', (string) $this->config->get( 'trusted_proxy_cidrs', '' ) );
		foreach ( $cidrs as $cidr ) {
			$cidr = trim( $cidr );
			if ( $cidr && $this->address_in_cidr( $address, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	private function address_in_cidr( $address, $cidr ) {
		$parts = explode( '/', $cidr, 2 );
		$network = $this->valid_address( $parts[0] );
		if ( ! $network ) {
			return false;
		}

		$address_bin = inet_pton( $address );
		$network_bin = inet_pton( $network );
		if ( false === $address_bin || false === $network_bin || strlen( $address_bin ) !== strlen( $network_bin ) ) {
			return false;
		}

		$bits = 8 * strlen( $address_bin );
		$prefix = isset( $parts[1] ) ? (int) $parts[1] : $bits;
		if ( $prefix < 0 || $prefix > $bits ) {
			return false;
		}

		$full_bytes = (int) floor( $prefix / 8 );
		$remaining  = $prefix % 8;
		if ( $full_bytes && substr( $address_bin, 0, $full_bytes ) !== substr( $network_bin, 0, $full_bytes ) ) {
			return false;
		}
		if ( $remaining ) {
			$mask = chr( ( 0xff << ( 8 - $remaining ) ) & 0xff );
			return ( ord( $address_bin[ $full_bytes ] ) & ord( $mask ) ) === ( ord( $network_bin[ $full_bytes ] ) & ord( $mask ) );
		}

		return true;
	}
}
