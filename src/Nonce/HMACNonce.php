<?php

namespace RB\Sphinx\Hmac\Nonce;

use RB\Sphinx\Hmac\Exception\HMACNonceException;

/**
 *
 * @author Reinaldo Borges
 *        
 */
abstract class HMACNonce {
	
	/**
	 *
	 * @var string
	 */
	protected $nonce = null;
	
	/**
	 * Gera novo nonce.
	 *
	 * @return string
	 */
	public abstract function generate();
	
	/**
	 * Verificar se nonce informado atende aos requisitos
	 *
	 * @param string $nonce        	
	 * @return bool
	 * @throws HMACNonceException
	 */
	public abstract function validate($nonce = NULL);
	
	/**
	 * Retorna nonce.
	 * Gera um novo se ainda não existir.
	 *
	 * @return string
	 */
	public function getNonce() {
		if ($this->nonce === null)
			$this->generate ();
		return $this->nonce;
	}
	
	/**
	 *
	 * @param string $nonce        	
	 * @return \RB\Sphinx\Hmac\Nonce\HMACNonce
	 */
	public function setNonce($nonce) {
		$this->nonce = $nonce;
		return $this;
	}
	
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