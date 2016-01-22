<?php

namespace RB\Sphinx\Hmac\Algorithm;

use RB\Sphinx\Hmac\Exception\HMACAlgorithmException;
use RB\Sphinx\Hmac\HMAC;

/**
 *
 * @author Reinaldo Borges
 *        
 */
abstract class HMACAlgorithm {
	/**
	 * Implementa o algoritmo de cálculo do HMAC.
	 *
	 * @param HMAC $hmac        	
	 * @param string $data        	
	 * @return string
	 *
	 * @throws HMACAlgorithmException
	 */
	public abstract function getHmac(HMAC $hmac, $data);
	
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