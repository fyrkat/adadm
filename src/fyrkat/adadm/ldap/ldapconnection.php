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
	 * @param array $options LDAP options
	 */
	public function __construct(string $host, string $userdn, string $password, array $options = []) {
		$options['protocol'] = $options['protocol'] ?? 'ldap';
		$options['port'] = $options['port'] ?? (
				$options['protocol'] === 'ldaps' ? 636 : 389
			);
		$options['ldap_options'] = $options['ldap_options'] ?? [];
		$options['ldap_options'][LDAP_OPT_PROTOCOL_VERSION] = $options['ldap_options'][LDAP_OPT_PROTOCOL_VERSION] ?? 3;
		$options['starttls'] = $options['starttls'] ?? true;

		$url = $options['protocol'] . '://' . $host;

		$this->host = $host;
		$this->userdn = $userdn;
		$this->options = $options;
		$this->url = $url;
		$this->ldap = ldap_connect( $url, $port );

		if ( !$ldap ) {
			throw new \Exception('Unable to connect to LDAP server.');
		}

		foreach($options['ldap_options'] as $key => $value) {
			ldap_set_option( $this->ldap, $key, $value );
		}
		$bind = ldap_bind( $this->ldap, $username, $password );

		if ( !$bind ) {
			if (ldap_get_option($this->ldap, 0x0032, $extendedError)) {
				throw new \Exception( $extendedError );
			}
			throw \Exception( 'Unable to bind LDAP server, invalid credentials?' );
		}
	}

}
