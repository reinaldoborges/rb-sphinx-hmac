<?php

namespace RB\Sphinx\Hmac\Nonce;

use RB\Sphinx\Hmac\Exception\HMACNonceException;

/**
 * Nonce com TIME STAMP e parte pseudo aleatória.
 *
 * @author Reinaldo Borges
 *        
 */
class SimpleTSNonce extends HMACNonce {
	
	/**
	 * Maior diferença (em segundos) entre o TimeStamp do nonce a ser verificado e o
	 * timestamp atual.
	 *
	 * @var number
	 */
	const TIMEOUT = 900; // segundos
	
	/**
	 * Número de dígitos pseudo-aleatórios antes do TimeStamp
	 *
	 * @var number
	 */
	protected $numDigitosAleatorios = 0;
	
	/**
	 *
	 * @param number $numDigitosAleatorios        	
	 */
	public function __construct($numDigitosAleatorios = 0) {
		$this->numDigitosAleatorios = $numDigitosAleatorios;
	}
	
	/**
	 * (non-PHPdoc)
	 *
	 * @see \RB\Sphinx\Hmac\Nonce\HMACNonce::generate()
	 */
	public function generate() {
		
		/**
		 * Gerar parte pseudo-aleatória antes do time stamp
		 */
		$rand = '';
		if ($this->numDigitosAleatorios > 0) {
			$rand = sha1 ( rand () ); // SHA1 gera 40 caracteres
			$rand = substr ( $rand, rand ( 0, 39 - $this->numDigitosAleatorios ), $this->numDigitosAleatorios );
		}
		
		$this->nonce = $rand . time ();
		
		return $this->nonce;
	}
	
	/**
	 * (non-PHPdoc)
	 *
	 * @see \RB\Sphinx\Hmac\Nonce\HMACNonce::validate()
	 */
	public function validate($nonce = NULL) {
		if ($nonce === NULL)
			$nonce = $this->nonce;
		
		/**
		 * Extrair TIMESTAMP do nonce
		 */
		$timestamp = substr ( $nonce, $this->numDigitosAleatorios ) + 0;
		$now = time ();
		if ((abs ( $timestamp - $now ) <= self::TIMEOUT / 2) == false)
			throw new HMACNonceException ( "Simple TS Nonce fora do intervalo aceitável", 1 );
		
		return true;
	}
}