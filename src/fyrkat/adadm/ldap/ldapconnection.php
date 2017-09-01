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
	 * @see https://php.net/ldap_set_option
	 * @see https://php.net/ldap_start_tls
	 *
	 * @param string $host LDAP hostname
	 * @param string $userdn LDAP user DN
	 * @param string $password LDAP password
	 * @param string $basedn Base DN, used as default
	 * @param array $options LDAP options
	 */
	public function __construct(string $host, string $userdn, string $password, string $basedn = null, array $options = []) {
		$options['protocol'] = $options['protocol'] ?? 'ldap';
		$options['port'] = $options['port'] ?? (
				$options['protocol'] === 'ldaps' ? 636 : 389
			);
		$options['ldap_options'] = $options['ldap_options'] ?? [];
		$options['ldap_options'][LDAP_OPT_PROTOCOL_VERSION] = $options['ldap_options'][LDAP_OPT_PROTOCOL_VERSION] ?? 3;
		$options['starttls'] = $options['starttls'] ?? true;

		$url = $options['protocol'] . '://' . $host;

		$this->host = $host;
		$this->basedn = $basedn;
		$this->userdn = $userdn;
		$this->options = $options;
		$this->url = $url;
		$this->ldap = ldap_connect( $url, $options['port'] );

		if ( !$this->ldap ) {
			throw new \Exception('Unable to connect to LDAP server.');
		}

		if ( $options['starttls'] ) {
			ldap_start_tls( $this->ldap );
		}

		foreach($options['ldap_options'] as $key => $value) {
			ldap_set_option( $this->ldap, $key, $value );
		}
		$bind = ldap_bind( $this->ldap, $userdn, $password );

		if ( !$bind ) {
			if (ldap_get_option( $this->ldap, LDAP_OPT_ERROR_STRING, $extendedError )) {
				throw new \Exception( $extendedError );
			}
			throw \Exception( 'Unable to bind LDAP server, invalid credentials?' );
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
	public function getObjectByDN(string $dn): LdapObject {
		return $this->getObjectByAttribute('dn', $dn, '');
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
	public function getObjectByAttribute(string $attribute, $value, string $basedn = null): LdapObject {
		if ( is_null( $basedn ) ) {
			$basedn = $this->basedn;
		}
		$search = ldap_read( $this->ldap, $basedn, "($attribute=" . ldap_escape($value) . ')', [], 0, 1 );
		return new LdapObject( $this, ldap_first_entry( $this->ldap, $search ) );
	}

}
