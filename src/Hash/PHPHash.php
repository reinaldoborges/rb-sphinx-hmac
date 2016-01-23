<?php

namespace RB\Sphinx\Hmac\Hash;

use RB\Sphinx\Hmac\Exception\HMACHashException;

/**
 * Biblioteca Hash do PHP
 *
 * @link http://php.net/manual/pt_BR/function.hash.php
 *      
 * @author Reinaldo Borges
 *        
 */
class PHPHash extends HMACHash {
	
	/**
	 * Algortimo a ser utilizado
	 *
	 * @var string
	 */
	protected $hashAlgo;
	public function __construct($hashAlgo) {
		/**
		 * Verificar se algoritmo está disponível
		 */
		$algoList = hash_algos ();
		if (array_search ( $hashAlgo, $algoList ) === FALSE)
			throw new HMACHashException ( 'Hash ' + $hashAlgo + ' não está disponível. Veja a lista em hash_algos().' );
		
		$this->hashAlgo = $hashAlgo;
	}
	
	/**
	 * (non-PHPdoc)
	 *
	 * @see \RB\Sphinx\Hmac\Hash\HMACHash::getHash()
	 */
	public function getHash($data) {
		return hash ( $this->hashAlgo, $data );
	}
	
	/**
	 * (non-PHPdoc)
	 *
	 * @see \RB\Sphinx\Hmac\Hash\HMACHash::__toString()
	 */
	public function __toString() {
		return strtr ( strtoupper ( $this->hashAlgo ), ',', '_' );
	}
}