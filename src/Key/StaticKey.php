<?php

namespace RB\Sphinx\Hmac\Key;

use RB\Sphinx\Hmac\Exception\HMACKeyException;
use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\Algorithm\HMACAlgorithm;

/**
 *
 * @author Reinaldo Borges
 *        
 */
class StaticKey extends HMACKey {
	
	/**
	 *
	 * @var string
	 */
	protected $key = NULL;
	
	/**
	 *
	 * @param string $key
	 *        	Chave estática a ser utilizada
	 */
	public function __construct($key) {
		$this->key = $key;
	}
	
	/**
	 * (non-PHPdoc)
	 *
	 * @see \RB\Sphinx\Hmac\Key\HMACKey::getKeyString()
	 */
	public function getKeyValue($keyId = NULL) {
		$this->setId ( $keyId );
		
		if ($this->key === NULL)
			throw new HMACKeyException ( 'Chave não definida', 101 );
		
		return $this->key;
	}
	
}