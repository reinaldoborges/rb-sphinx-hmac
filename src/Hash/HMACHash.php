<?php

namespace RB\Sphinx\Hmac\Hash;

use RB\Sphinx\Hmac\Exception\HMACHashException;

/**
 *
 * @author Reinaldo Borges
 *        
 */
abstract class HMACHash {
	
	/**
	 * Calcula o HASH a ser utilizado pelo HMAC.
	 *
	 * @param string $data
	 *        	Dados de entrada da função de hash
	 * @return string
	 * @throws HMACHashException
	 */
	public abstract function getHash($data);
	
	/**
	 *
	 * @return string
	 */
	public function __toString() {
		$class = get_class ( $this );
		$namespace = __NAMESPACE__;
		
		return substr ( $class, strlen ( $namespace ) + 1 );
	}
}