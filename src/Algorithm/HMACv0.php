<?php

namespace RB\Sphinx\Hmac\Algorithm;

use RB\Sphinx\Hmac\Exception\HMACAlgorithmException;
use RB\Sphinx\Hmac\HMAC;

/**
 *
 * @author Reinaldo Borges
 *        
 */
class HMACv0 extends HMACAlgorithm {
	/**
	 * Implementa o algoritmo de cálculo do HMAC.
	 *
	 * @param HMAC $hmac        	
	 * @param string $data        	
	 * @return string
	 *
	 * @throws HMACAlgorithmException
	 */
	public function getHmac(HMAC $hmac, $data) {
		return $hmac->getHash ( $hmac->getHash ( $hmac->getCompositeKey () ) . $data );
	}
}