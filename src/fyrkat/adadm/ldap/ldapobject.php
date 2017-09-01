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
	/** @var array LDAP attributes */
	private $entry;
	/** @var string Lazy loaded distinguished name */
	private $dn;
	/** @var array Lazy loaded attributes */
	private $attributes;

	/**
	 * Construct new object.
	 * This is called from LdapConnection
	 *
	 * @param LdapConnection $ldap Calling LdapConnection
	 * @param array $entry Attributes in this object
	 * @param bool $new Assume that this object is new, don't try to update it
	 */
	public function __construct(LdapConnection $ldap, array $entry, bool $new = false) {
		$this->ldap = $ldap;
		$this->entry = $entry;
		$this->new = $new;
		$this->dn = $entry['dn'];
		$this->attributes = array_map( function($e){
				// array_slice to remove the first "count" object.
				return array_slice($e, 1);
			}, array_filter( $entry, function($k){
				// array is contaminated with integers, a "count" and "dn" field;
				// these are not proper ldap attributes.
				return !in_array($k, ['count', 'dn']) && is_string($k);
			}, ARRAY_FILTER_USE_KEY ) );
	}

	/**
	 * Return the DN of the object.
	 *
	 * @return string Distinguished name
	 */
	public function getDN(): string {
		return $this->dn;
	}

	/**
	 * Return all values for the given attribute.
	 *
	 * @param string $attribute Name of the attribute
	 *
	 * @return array All values for the requested attribute
	 */
	public function getAttribute(string $attribute): array {
		// PHP LDAP library converts all array keys to lowercase.
		return $this->attributes[strtolower( $attribute )];
			);
	}

}
