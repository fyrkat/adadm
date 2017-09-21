<?php
/**
 * LDAP Exception
 *
 * @copyright Copyright (c) 2017 Jørn Åne de Jong <@jornane>
 */

declare(strict_types=1);

namespace fyrkat\adadm\ldap;

use \Exception;
use \RuntimeException;

/**
 * LDAP exception
 *
 * This exception is ued when an LDAP operation fails for some reason.
 * Its goal is to 
 *
 * @see https://php.net/ldap_get_option
 */
class LdapException extends RuntimeException {

	/**
	 * Read the extended error string from an LDAP resource
	 *
	 * This string may often be more useful than the result of ldap_error()
	 *
	 * @param resource $ldapResource The resource to read the string from
	 *
	 * @return string The extended error string
	 */
	static function getExtendedError( $ldapResource ) {
		ldap_get_option( $ldapResource, LDAP_OPT_ERROR_STRING, $result );
		return $result;
	}

	/**
	 * Construct a new exception
	 *
	 * @param resource $ldapResource The resource to read the error message from
	 * @param Exception $previous The exception that triggered this exception
	 */
	public function __construct( $ldapResource, Exception $previous = null ) {
		parent::__construct(
				self::getExtendedError( $ldapResource ) ?? ldap_error( $ldapResource ),
				ldap_errno( $ldapResource ),
				$previous
			);
	}

}
