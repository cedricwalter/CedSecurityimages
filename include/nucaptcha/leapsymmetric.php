<?php
/**
 * @package   NuCaptcha PHP clientlib
 * @author    <support@nucaptcha.com> Leap Marketing Technologies Inc
 * @license   LGPL License 2.1 (see included license.txt)
 * @link      http://www.nucaptcha.com/api/php
 */

// we only want to redefine the client version of this class if we haven't already defined the non-client version
if(class_exists("lmSymmetricMessage", false))
{
	return;
}

/**
 * class lmSymmetricMessage
 * This class is intended to create a secure transfer protocol that
 * is validated by a symmetric key.  Validity is assumed by knowledge
 * of the enciphering key.
 *
 * This class is intended to be a singleton.
 *
 * Security Features:
 * - It needs to have a timestamp internal to the data package
 * - It should pass a new symmetric key used for further communication
 */
class lmSymmetricMessage
{
	static private $m_cipher	= MCRYPT_RIJNDAEL_128;	// Password function is hard coding the keysize
	static private $m_mode		= MCRYPT_MODE_CBC;
	static private $m_METHODID	= 0;	// Method is for future .. default is 0
	static private $m_type		= 1;
	static private $m_PIPE		= '.';
	static private $m_magic		= "LEAPSM";				// Some magic data to prepend to the encrypted data to ensure validity

	/**
	 * Length of a valid base64 Encoded IV
	 *
	 * @var int
	 */
	static private $sIvLength = 24;

	static private $e_VERSION		= 0;
	static private $e_SENDERID		= 1;
	static private $e_KEYID			= 2;
	static private $e_METHOD		= 3;
	static private $e_IV			= 4;
	static private $e_DATA			= 5;

	/**
	 * SymmetricEncipher:
	 * This will encipher a message and return it (as binary)
	 *
	 * @param binary $key
	 * @param binary $iv
	 * @param binary $message
	 * @return binary
	 */
	static public function SymmetricEncipher($key, $iv, $message)
	{
		// Figure out how much padding is required.  If full key size, don't pad.
		$keysize = (lmSymmetricMessage::GetKeySizeInBytes());
		$carry   = ((strlen(lmSymmetricMessage::$m_magic) + 1 + strlen($message)) % $keysize);
		$padsize = ($keysize - $carry);		// Will be -1 .. Must +1 on decode

		// If no padding required
		if (0 == $carry)
		{
			// No extra padding required
			$msg = lmSymmetricMessage::$m_magic."0".$message;
		}
		else
		{
			// Add the padding
			$msg = lmSymmetricMessage::$m_magic.str_repeat(dechex($padsize), $padsize+1).$message;
		}

		// Encipher the data
		return mcrypt_encrypt(lmSymmetricMessage::$m_cipher, $key, $msg, lmSymmetricMessage::$m_mode, $iv);
	}

	/**
	 * SymmetricDecipher:
	 * This will decipher a message and return it
	 *
	 * @param binary $key
	 * @param binary $iv
	 * @param binary $encmessage - the message
	 * @param bool $throw - whether or not to throw an exception on an error
	 * @return binary/bool - the deciphered message, or false if an error
	 */
	static public function SymmetricDecipher($key, $iv, $encmessage, $throw=true)
	{
		// Decipher the message
		$dec =  mcrypt_decrypt(lmSymmetricMessage::$m_cipher, $key, $encmessage, lmSymmetricMessage::$m_mode, $iv);

		// Check to see that our magic is on the front
		$magic = substr($dec, 0, strlen(lmSymmetricMessage::$m_magic));

		if (0 != strcmp($magic, lmSymmetricMessage::$m_magic))
		{
			if (true === $throw)
			{
				$error_data = array(
					'symmetric-decipher-key' => base64_encode($key),
					'symmetric-decipher-iv' => base64_encode($iv),
					// message is too big for hoptoad -- it truncates at 2kb.
					//'symmetric-decipher-encmessage' => base64_encode($encmessage),
					'symmetric-decipher-magic' => $magic,
					//'symmetric-decipher-dec' => $dec,
					// From http://ca2.php.net/manual/en/function.mcrypt-create-iv.php
					// Prior to 5.3.0, MCRYPT_RAND was the only one supported on Windows.
					'symmetric-decipher-supports-mcrypt-dev-urandom' => lmHelper::checkWindowsVersion(50300),
				);

				throw new LeapException(
					sprintf(
						"Invalid key - could not decipher. Magic (%s) does not match expected (%s)",
						$magic,
						lmSymmetricMessage::$m_magic
					),
					LMEC_INVALIDKEY,
					'',
					$error_data
				);
			}
			else return false;
		}

		// Get our padding size
		$pad = hexdec(substr($dec, strlen(lmSymmetricMessage::$m_magic), 1))+1;

		// Return the decoded data
		return substr($dec, strlen(lmSymmetricMessage::$m_magic)+$pad);
	}

	/**
	 * This will generate an initialization vector.  This can be passed
	 * in the open with no loss to security.
	 *
	 * Calls MCryptRandom()
	 *
	 * @return string (binary)
	 */
	static public function GenerateIV()
	{
		// attempt to generate a LeapIV first, then fall back
		// to a mcrypt iv
		return self::MCryptRandom(mcrypt_get_iv_size(lmSymmetricMessage::$m_cipher, lmSymmetricMessage::$m_mode));
	}

	/**
	 * Use mcrypte_create_iv to generate random data. Uses MCRYPT_DEV_URANDOM
	 * as a source
	 *
	 * @param int $size Size in bytes of random data to generate
	 * @return string
	 */
	static private function MCryptRandom($size)
	{
		lmGlobalPerformance::EnterSection('GenerateMcryptIV');

		// From http://ca2.php.net/manual/en/function.mcrypt-create-iv.php
		// Prior to 5.3.0, MCRYPT_RAND was the only one supported on Windows.
		if(false === lmHelper::checkWindowsVersion(50300))
		{
			$iv = mcrypt_create_iv($size, MCRYPT_RAND);
		}
		else
		{
			$iv = mcrypt_create_iv($size, MCRYPT_DEV_URANDOM);
		}
		lmGlobalPerformance::LeaveSection('GenerateMcryptIV');

		return $iv;
	}

	/**
	 * GenerateSymmetricKey:
	 * This will generate a random symmetric key.
	 *
	 * @return string (binary) - generated key
	 */
	static public function GenerateSymmetricKey()
	{
		return self::MCryptRandom(self::GetKeySizeInBytes());
	}

	/**
	 * Report the default key size, in bytes.
	 *
	 * @return int
	 */
	static public function GetKeySizeInBytes()
	{
	    return 16;
	}

	/**
	 * EncipherMessage:
	 * This will encipher a message with a symmetric cipher defined by
	 * lmSymmetricMessage::$m_cipher.  It will encode the output into
	 * a message structure.
	 *
	 * @param string $base64key - the key, encoded as base64
	 * @param string $message - the message to encode.
	 * @param int $senderid - the id of the sender (encoded in the message structure)
	 * @param int $keyid - the id of the key that was used
	 * @return string - SymmetricKeyStructure(v1)
	 */
	static public function EncipherMessage($base64key, $message, $senderid, $keyid)
	{
		// Grab the pipe character
		$pipe = lmSymmetricMessage::$m_PIPE;

		// Generate the IV
		$iv = lmSymmetricMessage::GenerateIV();

		// Encipher the message and return the package
		lmGlobalPerformance::EnterSection('EncodeBinaryMessage');
		$encoded = lmSymmetricMessage::$m_type . $pipe.
				$senderid . $pipe.
				$keyid . $pipe.
				lmSymmetricMessage::$m_METHODID . $pipe.
				lmBase64::EncodeBinary($iv) . $pipe.
				lmBase64::EncodeBinary(lmSymmetricMessage::SymmetricEncipher(lmBase64::DecodeBinary($base64key), $iv, $message));
		lmGlobalPerformance::LeaveSection('EncodeBinaryMessage');

		return $encoded;
	}

	/**
	 * DecipherMessage:
	 * This will decipher a given message with a given key.  It will ensure that
	 * the senderid is correct before it even tries.
	 *
	 * @param string $base64key - the key to use to decipher
	 * @param string $encmessage - message structure output from EncipherMessage
	 * @return string - deciphered message
	 */
	static public function DecipherMessage($base64key, $encmessage)
	{
		// Explode the message into its parts
		$msg = explode(lmSymmetricMessage::$m_PIPE, $encmessage);

		// Check to see if it's the correct type
		if (lmSymmetricMessage::$m_type != $msg[lmSymmetricMessage::$e_VERSION])
		{
			$error = "DecipherMessage unexpected version number: ".$msg[lmSymmetricMessage::$e_VERSION];

			if (LM_DEBUG)
			{
				$error .= "<BR><BR>Message:<BR>$encmessage<BR>";
			}

			throw new LeapException($error, LMEC_INVALIDVERSION);
		}

		// Ensure the IV is the correct size
		if (self::$sIvLength != strlen($msg[lmSymmetricMessage::$e_IV]))
		{
			throw new LeapException("Invalid encoded IV Length: ".strlen($msg[lmSymmetricMessage::$e_IV]), LMEC_INVALIDIVLENGTH);
		}

		return lmSymmetricMessage::SymmetricDecipher(lmBase64::DecodeBinary($base64key), lmBase64::DecodeBinary($msg[lmSymmetricMessage::$e_IV]), lmBase64::DecodeBinary($msg[lmSymmetricMessage::$e_DATA]));
	}

	/**
	 * GetSenderID:
	 * This will return the SenderID encoded inside the message structure
	 *
	 * @param string $encmessage - the encoded message structure
	 * @return int - int SenderID
	 */
	static public function GetSenderID($encmessage)
	{
		// Explode the message into its parts.  We don't really need the whole
		// message, just the first 2 elements.  Those are guaranteed to be in
		// the first 16 bytes
		$msg = explode(lmSymmetricMessage::$m_PIPE, substr($encmessage, 0, 16));

		// Check to see if it's the correct type
		if (lmSymmetricMessage::$m_type != $msg[lmSymmetricMessage::$e_VERSION])
		{
			$error = "DecipherMessage unexpected version number: ".$msg[lmSymmetricMessage::$e_VERSION];
			if (LM_DEBUG)
			{
				$error .= "<BR>Full Token: $encmessage<BR>";
			}
			throw new LeapException($error, LMEC_INVALIDVERSION);
		}

		// return the sender ID
		return $msg[lmSymmetricMessage::$e_SENDERID];
	}

	/**
	 * GetKeyID:
	 * This will return the KeyID encoded inside the message structure
	 *
	 * @param string $encmessage - the encoded message structure
	 * @return int - int KeyID
	 */
	static public function GetKeyID($encmessage)
	{
		// Explode the message into its parts.  We don't really need the whole
		// message, just the first 3 elements.  Those are guaranteed to be in
		// the first 32 bytes
		$msg = explode(lmSymmetricMessage::$m_PIPE, substr($encmessage, 0, 32));

		// Check to see if it's the correct type
		if (lmSymmetricMessage::$m_type != $msg[lmSymmetricMessage::$e_VERSION])
		{
			$error = "DecipherMessage unexpected version number: ".$msg[lmSymmetricMessage::$e_VERSION];
			if (LM_DEBUG)
			{
				$error .= "<BR>Full Token: $encmessage<BR>";
			}
			throw new LeapException($error, LMEC_INVALIDVERSION);
		}

		// return the sender ID
		return $msg[lmSymmetricMessage::$e_KEYID];
	}

	/**
	 * IsInvalid:
	 * This will determine whether a message is definitely INVALID.  This does not
	 * mean the message is valid, it just looks for markers that indicate that it's
	 * definitely not valid
	 *
	 * We should be able to quickly test the message form for correctness, given:
	 * version(int)
	 * senderid(int)
	 * keyid(int)
	 * method(int)
	 * iv(string(24))
	 * message(binary encoded string)
	 *
	 * @param string $encmessage
	 * @return bool
	 */
	static public function IsInvalid($encmessage)
	{
		// Explode the message
		$msg = explode(lmSymmetricMessage::$m_PIPE, $encmessage);

		// VERSION element must be an int or numeric
		if ( true !== ctype_digit($msg[lmSymmetricMessage::$e_VERSION]) )
		{
		    return true;
		}

		// If the version isn't proper
		if (lmSymmetricMessage::$m_type != $msg[lmSymmetricMessage::$e_VERSION])
		{
		    return true;
		}

		// SENDERID element must be an int or numeric
		if ( true !== ctype_digit($msg[lmSymmetricMessage::$e_SENDERID]) )
		{
		    return true;
		}

		// KEYID element must be an int or numeric
		if ( true !== ctype_digit($msg[lmSymmetricMessage::$e_KEYID]) )
		{
		    return true;
		}

		// METHOD element must be an int or numeric
		if ( true !== ctype_digit($msg[lmSymmetricMessage::$e_METHOD]) )
		{
		    return true;
		}

		if (self::$sIvLength != strlen($msg[lmSymmetricMessage::$e_IV]))
		{
		    return true;
		}

		if( lmBase64::IsValidBase64($msg[lmSymmetricMessage::$e_DATA]) )
		{
			return true;
		}

		// Everything seems ok
		return false;
	}
}
