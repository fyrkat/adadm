<?php
/**
 * LDAP Connection
 *
 * @copyright Copyright (c) 2017 Jørn Åne de Jong <@jornane>
 */

declare(strict_types=1);

namespace fyrkat\adadm\ldap;

/**
 * LDAP connection class.
 *
 * This class creates an PHP native LDAP resource,
 * which is then used for all LDAP operations.
 *
 * @see https://php.net/ldap_connect
 * @see https://php.net/ldap_bind
 * @see https://php.net/ldap_set_option
 * @see https://php.net/ldap_start_tls
 */

class LdapConnection {

	/** @var string user-provided hostname */
	private $host;
	/** @var string user-provided base DN */
	private $basedn;
	/** @var string user-provided user DN */
	private $userdn;
	/** @var array various options */
	private $options;
	/** @var string calculated LDAP url for use in ldap_connect */
	private $url;
	/** @var resource LDAP resource */
	protected $ldap;

	/**
	 * Connect to LDAP and authenticate.
	 * If connection or authentication fails,
	 * an exception is returned.
	 *
	 * The following options are available:
	 * - protocol: `ldaps` or `ldap` (default `ldap`)
	 * - port: portnumber (default 636 if protocol is `ldaps`, 389 otherwise)
	 * - ldap_options: options like in `ldap_set_option` (default protocol version is set to 3)
	 * - starttls: whether starttls should be used (default true)
	 *
	 * @see https://php.net/ldap_connect
	 * @see https://php.net/ldap_bind
	 * @see https://php.net/ldap_set_option
	 * @see https://php.net/ldap_start_tls
	 *
	 * @param string $host LDAP hostname
	 * @param string $userdn LDAP user DN (AD also allows userPrincipalName here)
	 * @param string $password LDAP password
	 * @param string $basedn Base DN, used as default
	 * @param array $options LDAP options
	 */
	public function __construct( string $host, string $userdn, string $password,
			string $basedn = null, array $options = [] ) {
		$options['protocol'] = $options['protocol'] ?? 'ldap';
		$options['port'] = $options['port'] ?? (
				$options['protocol'] === 'ldaps' ? 636 : 389
			);
		$options['ldap_options'] = $options['ldap_options'] ?? [];
		$options['ldap_options'][LDAP_OPT_PROTOCOL_VERSION] =
			$options['ldap_options'][LDAP_OPT_PROTOCOL_VERSION] ?? 3;
		$options['starttls'] = $options['starttls'] ?? true;

		$url = "$options[protocol]://$host";

		$this->host = $host;
		$this->basedn = $basedn;
		$this->userdn = $userdn;
		$this->options = $options;
		$this->url = $url;

		if ( false === $this->ldap = @ldap_connect( $url, $options['port'] ) ) {
			throw new LdapConnectSyntaxException( "$url:$options[port]" );
		}

		if ( $options['starttls'] ) {
			if ( false === @ldap_start_tls( $this->ldap ) ) {
				throw new LdapException( $this->ldap );
			}
		}

		foreach( $options['ldap_options'] as $key => $value ) {
			ldap_set_option( $this->ldap, $key, $value );
		}

		if ( false === @ldap_bind( $this->ldap, $userdn, $password ) ) {
			throw new LdapException( $this->ldap );
		}
	}

	/**
	 * Get an LDAP object by its distinguished name.
	 * The object must already exist in LDAP.
	 *
	 * @param string $dn Distinguished name of the object.
	 *
	 * @return LdapObject The object.
	 */
	public function getObjectByDN( string $dn ): LdapObject {
		return $this->getObjectByAttribute( 'dn', $dn, '' );
	}

	/**
	 * Get multiple LDAP objects by the value of one attribute.
	 *
	 * @param string $attribute attribute name
	 * @param mixed $value value for the attribute
	 * @param string $basedn base dn for searching
	 *
	 * @return LdapObject[] The object.
	 */
	public function getObjectsByAttribute( string $attribute, $value,
			string $basedn = null ): array {
		if ( is_null( $basedn ) ) {
			$basedn = $this->basedn;
		}
		$search = ldap_search(
				$this->ldap, $basedn,
				sprintf( '(%s=%s)', $attribute, ldap_escape( $value ) )
			);
		$entries = ldap_get_entries( $this->ldap, $search );
		unset( $entries['count'] );
		return array_map( function( $entry ) {
				return new LdapObject( $this, $entry );
			}, $entries );	
	}

	/**
	 * Get a single LDAP object by the value of one attribute.
	 * When the attribute's value is not unique, the first one found is returned.
	 *
	 * @param string $attribute attribute name
	 * @param mixed $value value for the attribute
	 * @param string $basedn base dn for searching
	 *
	 * @return LdapObject The object.
	 */
	public function getObjectByAttribute( string $attribute, $value,
			string $basedn = null ): LdapObject {
		return $this->getObjectsByAttribute( $attribute, $value, $basedn )[0];
	}

	/**
	 * Create a new object.  The new object will be marked as "new",
	 * so that it is created in the LDAP server when save() is called.
	 *
	 * @param string $dn Distinguished name of the object.
	 * @param array $attributes Preload the created object with these attributes
	 * @param bool $noCheck Do not check if the object already exists in the LDAP server
	 *
	 * @return LdapObject New LDAP object.
	 */
	public function createObjectByDN( string $dn, $attributes = [],
			$noCheck = false ): LdapObject {
		if ( !$noCheck && $this->getObjectByDN( $dn ) ) {
			throw new \DomainException( 'DN already exists' );
		}
		$o = new LdapObject( $this, ['distinguishedname' => $dn], true );
		foreach( $attributes as $key => $value ) {
			$o->setAttribute( $key, is_string( $value ) ? [$value] : $value );
		}
		return $o;
	}

	/**
	 * Write a modified LdapObject back to the server.
	 *
	 * Do not call this function directly, it should be called through
	 * LdapObject::save()
	 *
	 * @param LdapObject $o The LDAP object to write back.
	 */
	public function save( LdapObject $o ) {
		if ( $o->isNew() ) {
			$this->saveNew( $o );
		} else {
			$this->saveReplace( $o );
		}
	}

	/**
	 * Write a modified LdapObject back to the server.
	 * This function uses the replace strategy, which means that it will
	 * simply overwrite all attributes that have been changed.
	 *
	 * @param LdapObject $o The LDAP object to write back
	 */
	private function saveReplace( LdapObject $o ) {
		$dn = $o->getDN();
		if ( false === ldap_modify( $this->ldap, $dn, $o->getChangedAttributes() ) ) {
			throw new LdapException( $this->ldap );
		}
	}

	/**
	 * Write a modified LdapObject back to the server.
	 * This function uses the new strategy, which means that it will
	 * attempt to write the object as a new object.
	 * This will probably fail if the object already exists.
	 *
	 * @param LdapObject $o The LDAP object to write
	 */
	private function saveNew( LdapObject $o ) {
		$dn = $o->getDN();
		if ( false === ldap_add( $this->ldap, $dn, $o->getChangedAttributes() ) ) {
			throw new LdapException( $this->ldap );
		}
		$o->setNew( false );
	}

}
