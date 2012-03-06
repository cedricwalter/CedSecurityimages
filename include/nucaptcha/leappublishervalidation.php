<?php
/**
 * @package   NuCaptcha PHP clientlib
 * @author    <support@nucaptcha.com> Leap Marketing Technologies Inc
 * @license   LGPL License 2.1 (see included license.txt)
 * @link      http://www.nucaptcha.com/api/php
 */
	
class lmPublisherValidation extends lmValidationInterface
{
	/**
	 * LMEC error code; LMEC_CORRECT if the answer was correct
	 *
	 * @var int
	 */
	private $mValid = LMEC_EMPTY;

	/**
	 * The LMRC_ code sent with the validation response
	 *
	 * @var int
	 */
	private $mResponseCode = 0;

	/**
	 * IsValid:
	 * Returns true if the response entered by the user was valid
	 *
	 * @return boolean
	 */
	public function GetValidationCode()
	{
		return $this->mValid;
	}

	/**
	 * GetResponseType:
	 * Returns an LMRC_ define indicating more information about the user's response
	 *
	 * @return int
	 */
	public function GetResponseType()
	{
		return $this->mResponseCode;
	}

	/**
	 * ValidateTransaction:
	 * This will validate the transaction and return true/false if it was correct.
	 * The error code will give more detail if not correct.
	 *
	 * @param string $persistentData	- Data stored to recreate the lmTransaction object
	 * @param lmResponse $response		- What the user responded with
	 */
	public function ValidateTransaction($persistentData, $response)
	{
		$chunk = $this->CreateValidationRequestChunk($response);
		$this->ValidateTransactionData($chunk, $persistentData);
	}

	public function GetTransactionID($persistentData)
	{
		$tid = '';
		try
		{
			$chunk = lmTextChunk::Decode($persistentData, "PDATA");
			if( $chunk->ChunkExists("TOKEN") )
			{
				$tid = lmHelper::GetIVFromToken($chunk->GetChunk("TOKEN"));
			}
		}
		catch( Exception $e )
		{
		}
		return $tid;
	}

	/**
	 * CreateValidationRequestChunk:
	 * Creates a text chunk to be sent to the validation server, filling it with the fields
	 * from the form on the HTML displayed to the user
	 *
	 * @param lmResponse $response		- What the user responded with (false = figure it out ourself)
	 * @return text chunk 				- the chunk to send to the validation server
	 */
	protected function CreateValidationRequestChunk($response)
	{
		// ***
		// *** Create the Validation Request
		// ***
		$chunk = lmHelper::CreateRequestChunk("VREQ", false);
		// set the answer and associated fields
		$response->SetValidationFields($chunk);
		
		return $chunk;
	}

	const SEND_VREQ_ATTEMPTS = 4;

	/**
	 * ValidateTransactionData:
	 * This will validate the transaction and return true/false if it was correct.
	 * The error code will give more detail if not correct.
	 *
	 * @param string $persistentData	- Data stored to recreate the lmTransaction object
	 * @param lmResponse $response		- What the user responded with (false = figure it out ourself)
	 */
	protected function ValidateTransactionData($chunk, $persistentData)
	{
		if( Leap::GetTestAction() === 'exception-validate' )
		{
			throw new Exception("Test exception-validate", LMEC_TEST);
		}

		// ***
		// *** Open and validate the lmTransaction
		// ***
		$transaction = lmTextChunk::Decode($persistentData, "PDATA");

		if( $transaction->ChunkExists("EREPORT") )
		{
			Leap::SetReportingMode($transaction->GetChunk("EREPORT"));
		}

		// Confirm that the token data is in the right place
		if (!$transaction->ChunkExists("SKEY") ||
			!$transaction->ChunkExists("TOKEN") ||
			!$transaction->ChunkExists("VSERV"))
		{
			throw new Exception("PERSISTENT DATA NOT VALID", LMEC_INVALIDPERSISTENT);
		}
		
		$key = lmHelper::GetClientKey();
		// *** Create the Request
		$req = lmSymmetricMessage::EncipherMessage(
				$transaction->GetChunk("SKEY"),
				$chunk->Export(),
				$key->GetChunk("CID"),
				$key->GetChunk("KID")
		);
		$message = "$req&token=" . $transaction->GetChunk("TOKEN");

		$success = false;
		$attempt = 1;
		while( $success === false && $attempt <= lmPublisherValidation::SEND_VREQ_ATTEMPTS )
		{
			$validateServer = '';
			try
			{
				$validateServer = $attempt < lmPublisherValidation::SEND_VREQ_ATTEMPTS ?
													$transaction->GetChunk("VSERV") :
													LM_FALLBACK_VALIDATE_SERVER;
				$encresp = lmRPCLite::Call($validateServer, $message);
				$success = true;
			}
			catch(Exception $e)
			{
				lmErrorReporter::SetErrorData('sendVREQ-Attempt-' . $attempt, $validateServer);

				if( $attempt == lmPublisherValidation::SEND_VREQ_ATTEMPTS )
				{
					lmErrorReporter::SetErrorData('sendVREQ-Attempts', $attempt);
					throw $e;
				}
				else
				{
					$attempt++;
				}
			}
		}
		
		// Is the encoded response definitely not valid?
		if (lmSymmetricMessage::IsInvalid($encresp))
		{   
			// See if we can decode it - is it an error?
			$error = LeapException::Import($encresp, $key->GetChunk("SKEY"));
			if (null == $error)
			{
				throw new Exception("INVALID VALIDATION RESPONSE " . $encresp, LMEC_INVALIDVRES);
			}
			else
			{
				throw new Exception($error->GetChunk("EMSG"), $error->GetChunk("ECODE"));
			}
		}
		// ***
		// *** Decipher the validation response
		// ***
		$tokenchunk	= lmSymmetricMessage::DecipherMessage($transaction->GetChunk("SKEY"), $encresp);
		if (false === $tokenchunk)
		{
			throw new Exception("INVALID VALIDATION RESPONSE" . $encresp, LMEC_INVALIDVRES);
		}
		// *** Decode the textchunk
		$chunk = lmTextChunk::Decode($tokenchunk, "VRES");
		// Is it the wrong type?
		if (0 != strcmp($chunk->GetChunk("TYPE"), "VRES"))
		{
			// See if we can decode it - is it an error?
			$error = LeapException::Import($encresp, $key->GetChunk("SKEY"));
			if (null == $error)
			{
				throw new Exception("INVALID TYPE: ".$chunk->GetChunk("TYPE"), LMEC_INVALIDVRES);
			}
			else
			{
				throw new Exception($error->GetChunk("EMSG"), $error->GetChunk("ECODE"));
			}
		}

		// *** Validate the Time Stamp
		//TODO:
		// *** Figure out if the chunk is valid
		$this->SetValid($chunk->GetChunk("VALID"));

		// get the response code too
		if ($chunk->ChunkExists("LMRC"))
		{
			$this->SetResponseCode($chunk->GetChunk("LMRC"));
		}
	}

	/**
	 * SetValid:
	 * Called by child classes to set the valid field
	 *
	 * @param int $value	- The new value to set the valid member to
	 */
	protected function SetValid( $value )
	{
		$this->mValid = $value;
	}

	/**
	 * SetResponseCode:
	 * Called by child classes to set the response code field
	 *
	 * @param int $value	- The new value to set the response code member to
	 */
	protected function SetResponseCode( $value )
	{
		$this->mResponseCode = $value;
	}
}
