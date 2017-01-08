<?php
/**
 * LDAP Object
 *
 * @copyright Copyright (c) 2017 Jørn Åne de Jong <@jornane>
 */

declare(strict_types=1);

namespace fyrkat\adadm\ldap;

/**
 * LDAP object.
 *
 * Instances of this class can be returned from LdapConnection.
 */

class LdapObject {

	/** @var LdapConnection Calling LdapConnection */
	private $ldap;
	/** @var resource LDAP result entry */
	private $entry;
	/** @var string Lazy loaded distinguished name */
	private $dn;
	/** @var array Lazy loaded attributes */
	private $attributes;

	/**
	 * Construct new object.
	 * This is called from LdapConnection
	 *
	 * @param resource $ldap Calling LdapConnection
	 * @param resource $entry LDAP result entry
	 */
	public function __construct($ldap, $entry) {
		if ( !is_resource( $ldap ) ) {
			throw new \Exception( '$ldap must be a resource.' );
		}
		if ( !is_resource( $entry ) ) {
			throw new \Exception( '$entry must be a resource.' );
		}
		$this->ldap = $ldap;
		$this->entry = $entry;
	}

	/**
	 * Return the DN of the object.
	 *
	 * @return string Distinguished name
	 */
	public function getDN(): string {
		if ( isset( $this->dn ) ) {
			return $this->dn;
		}
		return $this->dn = ldap_get_dn( $this->ldap, $this->entry );
	}

	/**
	 * Return all values for the given attribute.
	 *
	 * @param string $attribute Name of the attribute
	 *
	 * @return array All values for the requested attribute
	 */
	public function getAttribute(string $attribute) {
		if ( !isset( $this->attributes ) ) {
			$this->attributes = ldap_get_attributes( $this->ldap, $this->entry );
		}
		return array_filter(
				$this->attributes[$attribute],
				function($k){return $k !== 'count';},
				ARRAY_FILTER_USE_KEY
			);
	}

}
