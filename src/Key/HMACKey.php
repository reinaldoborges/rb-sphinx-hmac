<?php

namespace RB\Sphinx\Hmac\Key;

use RB\Sphinx\Hmac\Algorithm\HMACAlgorithm;
use RB\Sphinx\Hmac\HMACSession;
use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\Exception\HMACKeyException;

/**
 *
 * @author Reinaldo Borges
 *        
 */
abstract class HMACKey {
	
	/**
	 *
	 * @var string
	 */
	protected $keyId;
	
	/**
	 *
	 * @return string
	 */
	public function getId() {
		return $this->keyId;
	}
	
	/**
	 *
	 * @param string $keyId        	
	 * @return \RB\Sphinx\Hmac\Key\HMACKey
	 */
	protected function setId($keyId) {
		$this->keyId = $keyId;
		return $this;
	}
	
	/**
	 * Retorna a string da chave a ser utilizada
	 *
	 * @param string $keyId        	
	 * @return string
	 */
	public abstract function getKeyValue($keyId);
	
	/**
	 * Retornar chave composta a ser usada no HMAC
	 *
	 * @param HMAC $hmac        	
	 * @param HMACAlgorithm $algo        	
	 * @param array $parametros        	
	 * @return string
	 */
	public function getCompositeKey(HMAC $hmac) {
		$hmacKey = '';
		$algo = $hmac->getAlgorithm ();
		$this->setId( $hmac->getKeyId() );
		
		if ($hmac instanceof HMACSession) {
			/**
			 * Composição da chave para HMAC com Sessão
			 */
			
			if ($hmac->getDataType () === NULL)
				throw new HMACKeyException ( 'Chave precisa do DATATYPE para sua composição', 3 );
			
			/**
			 * Ajustar composição de acordo com o tipo da mensagem
			 */
			switch ($hmac->getDataType ()) {
				case HMACSession::SESSION_REQUEST :
					/**
					 * Requisição de início de sessão:
					 * NONCE + KEY
					 */
					$hmacKey = $hmac->getNonceValue () . $this->getKeyValue ( $this->keyId );
					break;
				case HMACSession::SESSION_RESPONSE :
					/**
					 * Resposta à requisição de início de sessão:
					 * NONCE + KEY + NONCE2
					 */
					
					$hmacKey = $hmac->getNonceValue () . $this->getKeyValue ( $this->keyId ) . $hmac->getNonce2Value ();
					break;
				case HMACSession::SESSION_MESSAGE :
					/**
					 * Mensagens dentro da sessão:
					 * NONCE + KEY + CONTADOR + NONCE2
					 */
					if ($hmac->getContador () === NULL || $hmac->getContador () === 0)
						throw new HMACKeyException ( "Sessão HMAC não iniciada", 5 );
					
					$hmacKey = $hmac->getNonceValue () . $this->getKeyValue ( $this->keyId ) . $hmac->getContador () . $hmac->getNonce2Value ();
					break;
				default :
					throw new HMACKeyException ( "Tipo de mensagem HMAC desconhecida", 6 );
			}
		} elseif ($hmac instanceof HMAC) {
			/**
			 * Composição da chave para HMAC simples (sem sessão)
			 */
			$hmacKey = $hmac->getNonceValue () . $this->getKeyValue ( $this->keyId );
		} else {
			throw new HMACKeyException ( 'Tipo de HMAC desconhecido', 1 );
		}
		
		return $hmacKey;
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