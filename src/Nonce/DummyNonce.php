<?php

namespace RB\Sphinx\Hmac\Nonce;

/**
 * !!! ATENÇÃO !!!
 * Não gera o nonce, apenas mostra os dados em TEXTO CLARO.
 * Propósito didático para demonstrar funcionamento do protocolo.
 *
 * NÃO USE EM AMBIENTE DE PRODUÇÃO!!!
 *
 * @author Reinaldo Borges
 *        
 */
class DummyNonce extends HMACNonce {
	public function generate() {
		$this->nonce = '[NONCE]';
		return $this->nonce;
	}
	public function validate($nonce = NULL) {
		return true;
	}
}