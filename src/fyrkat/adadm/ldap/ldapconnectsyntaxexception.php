<?php
/**
 * LDAP Connect Exception
 *
 * @copyright Copyright (c) 2017 Jørn Åne de Jong <@jornane>
 */

declare(strict_types=1);

namespace fyrkat\adadm\ldap;

use \Exception;
use \RuntimeException;

/**
 * LDAP connection failure.
 *
 * This exception indicates that PHP deemed the LDAP connection to be
 * syntacically impossible, and never attempted a network connection.
 *
 * @see https://php.net/ldap_connect
 */
class LdapConnectSyntaxException extends RuntimeException {

	/**
	 * Construct a new Exception.  It takes in the LDAP connection URL and
	 * prefixes it with a string explaining the failure, so that an admin
	 * hopefully understands what's going on when reading the server logs.
	 *
	 * @param string $url The URL used to connect to the LDAP server, typically starts with ldap: or ldaps:
	 */
	public function __construct( string $url, int $code = 0, Exception $previous = null ) {
		parent::__construct( "Invalid LDAP connection settings for: $url", $code, $previous );
	}

}
