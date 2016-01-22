<?php

namespace RB\Sphinx\Hmac;

use RB\Sphinx\Hmac\Key\HMACKey;
use RB\Sphinx\Hmac\Hash\HMACHash;
use RB\Sphinx\Hmac\Nonce\HMACNonce;
use RB\Sphinx\Hmac\Exception\HMACException;
use RB\Sphinx\Hmac\Algorithm\HMACAlgorithm;

/**
 * HMAC Simples (sem sessão).
 *
 * @author Reinaldo Borges
 *        
 */
class HMAC {
	/**
	 *
	 * @var HMACHash;
	 */
	protected $hash;
	
	/**
	 *
	 * @var HMACAlgorithm
	 */
	protected $algo;
	
	/**
	 *
	 * @var HMACKey
	 */
	protected $key;
	
	/**
	 * Identificador da chave a ser usada no HMAC
	 *
	 * @var string
	 */
	protected $keyId;
	
	/**
	 *
	 * @var HMACNonce
	 */
	protected $nonce;
	
	/**
	 *
	 * @param HMACAlgorithm $algo        	
	 * @param HMACHash $hash        	
	 * @param HMACKey $key        	
	 * @param HMACNonce $nonce        	
	 */
	public function __construct(HMACAlgorithm $algo, HMACHash $hash, HMACKey $key, HMACNonce $nonce) {
		$this->algo = $algo;
		$this->hash = $hash;
		$this->key = $key;
		$this->nonce = $nonce;
	}
	
	/**
	 * Calcula o HMAC a partir dos dados informados e dos parâmetros já informados.
	 * Após informar KEYID.
	 *
	 * @param string $data        	
	 * @return string
	 */
	public function getHmac($data) {
		/**
		 * Delegar cálculo do HMAC
		 */
		$hmac = $this->algo->getHmac ( $this, $data );
		
		return $hmac;
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
	
	/**
	 *
	 * @return string
	 */
	public function getDescription() {
		return $this . '-' . $this->algo . '-' . $this->hash . '-' . $this->nonce;
	}
	
	/**
	 *
	 * @return \RB\Sphinx\Hmac\HMACHash;
	 */
	public function getHashObject() {
		return $this->hash;
	}
	
	/**
	 *
	 * @param string $data        	
	 * @return string
	 */
	public function getHash($data) {
		return $this->hash->getHash ( $data );
	}
	
	/**
	 * Verifica HMAC recebido após informar NONCE e KEYID
	 *
	 * @param string $data        	
	 * @param string $hmac        	
	 * @return boolean
	 * @throws HMACException
	 */
	public function validate($data, $hmac) {
		$hmacLocal = $this->getHmac ( $data );
		
		/**
		 * Comparar as duas strings de hash
		 */
		if (strcmp ( $hmac, $hmacLocal ) !== 0)
			throw new HMACException ( "HMAC informado é inválido", 1 );
		
		return true;
	}
	
	/**
	 * Informa valor do nonce
	 *
	 * @return string
	 */
	public function getNonceValue() {
		return $this->nonce->getNonce ();
	}
	
	/**
	 *
	 * @param string $nonceValue        	
	 * @return \RB\Sphinx\Hmac\HMAC
	 */
	public function setNonceValue($nonceValue) {
		/**
		 * Verifica o NONCE.
		 * Dispara exceção caso o nonce seja recusado.
		 */
		$this->nonce->validate ( $nonceValue );
		
		/**
		 * Registra nonce após validação
		 */
		$this->nonce->setNonce ( $nonceValue );
		return $this;
	}
	
	/**
	 * Retorna chave composto (que é gerada pelo HMACKey)
	 *
	 * @return string
	 */
	public function getCompositeKey() {
		return $this->key->getCompositeKey ( $this );
	}
	
	/**
	 *
	 * @return \RB\Sphinx\Hmac\Algorithm\HMACAlgorithm
	 */
	public function getAlgorithm() {
		return $this->algo;
	}
	
	/**
	 *
	 * @param string $keyId        	
	 * @return \RB\Sphinx\Hmac\HMAC
	 */
	public function setKeyId($keyId) {
		$this->keyId = $keyId;
		return $this;
	}
	
	/**
	 *
	 * @return string
	 */
	public function getKeyId() {
		return $this->keyId;
	}
}