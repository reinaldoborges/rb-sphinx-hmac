<?php

namespace RB\Sphinx\Hmac;

use RB\Sphinx\Hmac\Key\HMACKey;
use RB\Sphinx\Hmac\Hash\HMACHash;
use RB\Sphinx\Hmac\Nonce\HMACNonce;
use RB\Sphinx\Hmac\Exception\HMACException;
use RB\Sphinx\Hmac\Algorithm\HMACAlgorithm;

/**
 * HMAC com sessão
 *
 * @author reinaldo
 *        
 */
class HMACSession extends HMAC {
	const SESSION_REQUEST = 1;
	const SESSION_RESPONSE = 2;
	const SESSION_MESSAGE = 3;
	
	/**
	 * Tipo da mensagem, utilizado para definir a formação da CHAVE HMAC
	 *
	 * @var number
	 */
	protected $dataType = NULL;
	
	/**
	 * Nonce gerado pelo servidor para comunicação com sessão
	 *
	 * @var HMACNonce
	 */
	protected $nonce2;
	
	/**
	 * Contador da mensagem na sessão
	 *
	 * @var number
	 */
	protected $contador = NULL;
	
	/**
	 *
	 * @param HMACAlgorithm $algo        	
	 * @param HMACHash $hash        	
	 * @param HMACKey $key        	
	 * @param HMACNonce $nonce        	
	 * @param HMACNonce $nonce2        	
	 */
	public function __construct(HMACAlgorithm $algo, HMACHash $hash, HMACKey $key, HMACNonce $nonce, HMACNonce $nonce2) {
		parent::__construct ( $algo, $hash, $key, $nonce );
		$this->nonce2 = $nonce2;
	}
	
	/**
	 * Sinalizar início da sessão.
	 *
	 * @return \RB\Sphinx\Hmac\HMACSession
	 */
	public function startSession() {
		/**
		 * Indicar próxima mensagem esperada
		 */
		$this->contador = 1;
		
		return $this;
	}
	
	/**
	 * Prepara chave a ser utilizada pelo HMAC
	 * Com sessão, utiliza também o NONCE2 (gerado pelo servidor) e o CONTADOR da mensagem dentro da sessão
	 *
	 * @return string
	 * @throws HMACException
	 */
	protected function _getHmacKey() {
		/**
		 * Detectar tipo de mensagem pelo estado da sessão
		 */
		if ($this->dataType === NULL) {
			$this->dataType = self::SESSION_REQUEST;
		}
		
		/**
		 * Ajustar composição de acordo com o tipo da mensagem
		 */
		switch ($this->dataType) {
			case self::SESSION_REQUEST :
				/**
				 * Requisição de início de sessão:
				 * NONCE + KEY
				 */
				$hmacKey = $this->nonce->getNonce () . $this->key->getKeyString ( $this->keyId );
				break;
			case self::SESSION_RESPONSE :
				/**
				 * Resposta à requisição de início de sessão:
				 * NONCE + KEY + NONCE2
				 */
				if ($this->contador === NULL)
					throw new HMACException ( "Sessão HMAC não iniciada", 101 );
				
				$hmacKey = $this->nonce->getNonce () . $this->key->getKeyString ( $this->keyId ) . $this->nonce2->getNonce ();
				break;
			case self::SESSION_MESSAGE :
				/**
				 * Mensagens dentro da sessão:
				 * NONCE + KEY + CONTADOR + NONCE2
				 */
				$hmacKey = $this->nonce->getNonce () . $this->key->getKeyString ( $this->keyId ) . $this->contador . $this->nonce2->getNonce ();
				break;
			default :
				throw new HMACException ( "Tipo de mensagem HMAC desconhecida", 102 );
		}
		
		return $hmacKey;
	}
	
	/**
	 * Informa valor do nonce2 (gerado pelo servidor)
	 *
	 * @return string
	 */
	public function getNonce2Value() {
		return $this->nonce2->getNonce ();
	}
	
	/**
	 *
	 * @return number
	 */
	public function getContador() {
		return $this->contador;
	}
	
	/**
	 * (non-PHPdoc)
	 *
	 * @see \RB\Sphinx\Hmac\HMAC::getHmac()
	 */
	public function getHmac($data, $type = NULL) {
		if ($type !== NULL)
			$this->dataType = $type;
		
		/**
		 * Delegar cálculo do HMAC
		 */
		$hmac = $this->algo->getHmac ( $this, $data );
		
		return $hmac;
	}
	
	/**
	 * (non-PHPdoc)
	 *
	 * @see \RB\Sphinx\Hmac\HMAC::validate()
	 */
	public function validate($data, $hmac, $type = NULL) {
		if ($type !== NULL)
			$this->dataType = $type;
		
		$validate = parent::validate ( $data, $hmac );
		
		return $validate;
	}
	
	/**
	 *
	 * @return number
	 */
	public function getDataType() {
		return $this->dataType;
	}
	
	/**
	 * Incrementar contador, APÓS validar mensagem recebida e calcular HMAC da resposta
	 *
	 * @return \RB\Sphinx\Hmac\HMACSession
	 */
	public function nextMessage() {
		$this->contador ++;
		
		return $this;
	}
	
	/**
	 *
	 * @param string $nonceValue
	 * @return \RB\Sphinx\Hmac\HMAC
	 */
	public function setNonce2Value($nonceValue) {
		/**
		 * Verifica o NONCE.
		 * Dispara exceção caso o nonce seja recusado.
		 */
		$this->nonce2->validate ( $nonceValue );
	
		/**
		 * Registra nonce após validação
		*/
		$this->nonce2->setNonce ( $nonceValue );
		return $this;
	}
	
	
	/**
	 * (non-PHPdoc)
	 * 
	 * @see \RB\Sphinx\Hmac\HMAC::getDescription()
	 */
	public function getDescription() {
		return parent::getDescription () . '-' . $this->nonce2;
	}
}