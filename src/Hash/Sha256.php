<?php

namespace RB\Sphinx\Hmac\Hash;

use RB\Sphinx\Hmac\Exception\HMACHashException;

/**
 *
 * @author Reinaldo Borges
 *        
 */
class Sha256 extends HMACHash {
	/**
	 * (non-PHPdoc)
	 * 
	 * @see \RB\Sphinx\Hmac\Hash\HMACHash::getHash()
	 */
	public function getHash($data) {
		return hash ( 'sha256', $data );
	}
}