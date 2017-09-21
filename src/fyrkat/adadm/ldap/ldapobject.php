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
	/** @var array List of attributes that were touched */
	private $attributeLog;
	/** @var bool This object is new, used to create new LDAP objects */
	private $new;

	/**
	 * Construct new object.
	 * This is called from LdapConnection
	 *
	 * @param LdapConnection $ldap Calling LdapConnection
	 * @param array $entry Attributes in this object
	 * @param bool $new Assume that this object is new, don't try to update it
	 */
	public function __construct( LdapConnection $ldap, array $entry, bool $new = false ) {
		$this->ldap = $ldap;
		$this->entry = $entry;
		$this->new = $new;
		$this->dn = $entry['dn'];
		$this->attributes = array_map( function( $e ) {
				// array_slice to remove the first "count" object.
				return array_slice( $e, 1 );
			}, array_filter( $entry, function( $k ) {
				// array is contaminated with integers, a "count" and "dn" field;
				// these are not proper ldap attributes.
				return !in_array( $k, ['count', 'dn'] ) && is_string( $k );
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
	 * Indicates that this object is new.
	 * This means that it represents an LDAP object that has not been written
	 * to the LDAP server yet.
	 *
	 * @see #save()
	 *
	 * @return bool This object is new
	 */
	public function isNew(): bool {
		return $this->new;
	}

	/**
	 * Return all values for the given attribute.
	 *
	 * @param string $attribute Name of the attribute
	 *
	 * @return array All values for the requested attribute
	 */
	public function getAttribute( string $attribute ): array {
		// PHP LDAP library converts all array keys to lowercase.
		return $this->attributes[strtolower( $attribute )] ?? [];
	}

	/**
	 * Get all attributes that have been changed during the lifetime of this object.
	 * This is useful for writing all changes to LDAP.
	 *
	 * @return array Indexed array containing all attributes that were changed
	 *
	 * @see #setAttribute(string,array)
	 * @see #pushAttribute(string,string)
	 * @see #shiftAttribute(string,string)
	 * @see #removeAttribute(string,string)
	 */
	public function getChangedAttributes(): array {
		return array_map( function( $a ) {
			return array_values( $this->attributes[$a] );
		}, $this->attributeLog );
	}

	/**
	 * Set the values of an attribute.
	 * This will overwrite anything that was in the attribute before.
	 *
	 * @param string $attribute The name of the attribute
	 * @param array $values New values for this attribute
	 */
	public function setAttribute( string $attribute, array $values ) {
		$this->attributeLog[strtolower( $attribute )] = strtolower( $attribute );
		$this->attributes[strtolower( $attribute )] = $values;
	}

	/**
	 * Append a value to an attribute, like $attribute[] = $value.
	 * Any existing values are not touched, but if the value
	 * already existed, it will be duplicated.  There is no duplicate
	 * detection.
	 *
	 * @param string $attribute The name of the attribute
	 * @param string $value New value to append to the attribute
	 */
	public function pushAttribute( string $attribute, string $value ) {
		$this->attributeLog[strtolower( $attribute )] = strtolower( $attribute );
		$this->attributes[strtolower( $attribute )][] = $value;
	}

	/**
	 * Remove a value to an attribute, the opposite of pushAttribute().
	 * Only the vaule that exactly matches $value is removed.
	 * If the value is duplicate, only one is removed.
	 *
	 * Doesn't do anything if the value wasn't there to begin with.
	 *
	 * @param string $attribute The name of the attribute
	 * @param string $value New value to append to the attribute
	 *
	 * @return bool The value was found and removed
	 */
	public function shiftAttribute( string $attribute, string $value ): bool {
		$this->attributeLog[strtolower( $attribute )] = $attribute;
		$found = false;
		$this->attributes[strtolower( $attribute )] = array_filter(
				$this->getAttribute( $attribute ),
				function( $v ) use ( $value, &$found ) {
					if ($found) return true; // already removed one element
					$found = $v === $value;
					return !$found; // keep if not found
				}
			);
		if ( $found ) {
			$this->attributeLog[strtolower( $attribute )] = strtolower( $attribute );
		}
		return $found;
	}

	/**
	 * Entirely remove the attribute.
	 * This removes all values that were set before.
	 *
	 * @param string $attribute The name of the attribute
	 */
	public function removeAttribute( string $attribute ) {
		$this->setAttribute( $attribute, [] );
	}

	/**
	 * Write the local modifications back to the server.
	 *
	 * This function will simply call LdapConnection::save() but it may be
	 * preferred to use this function, because it will ensure that the
	 * connection that read this object and the connection that wrote the
	 * object are the same.
	 *
	 * If the object is new, it will be written as a new object, and the
	 * object will no longer be marked as new.
	 *
	 * @see #isNew()
	 */
	public function save() {
		$this->ldap->save( $this );
		$this->new = false;
	}

}
