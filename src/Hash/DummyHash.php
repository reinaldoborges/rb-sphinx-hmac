<?php

namespace RB\Sphinx\Hmac\Hash;

/**
 * !!! ATENÇÃO !!!
 * Não calcula o hash, apenas mostra os dados em TEXTO CLARO.
 * Propósito didático para demonstrar funcionamento do protocolo.
 * 
 * NÃO USE COM CHAVES REAIS OU AMBIENTE DE PRODUÇÃO!!!
 * 
 * @author Reinaldo Borges
 *        
 */
class DummyHash extends HMACHash {
	/**
	 * (non-PHPdoc)
	 * 
	 * @see \RB\Sphinx\Hmac\Hash\HMACHash::getHash()
	 */
	public function getHash($data) {
		return 'H(' . strtr($data,':','|') . ')';
	}
}