<?php
/**
 * @package   NuCaptcha PHP clientlib
 * @author    <support@nucaptcha.com> Leap Marketing Technologies Inc
 * @license   LGPL License 2.1 (see included license.txt)
 * @link      http://www.nucaptcha.com/api/php
 */

/**
 * Public interface for transaction objects.
 */
abstract class lmTransactionInterface
{
	/**
	 * The list of possible answers, returned in the token response from the token server
	 *
	 * @var Array
	 */
    private $mAnswers;

	/**
	 * A list of fields to query from the POST data.  Parsed from DDATA.
	 *
	 * @var string
	 */
	private $mResponseFieldData = Array();

	/**
	 * The key to send to the token server, that it should encrypt the token response with
	 *
	 * @var string
	 */
	private $mSessionKey;

	/**
	 * The data server to retrieve the gif or mp4 from
	 *
	 * @var url (string)
	 */
	private $mDataServer;

	/**
	 * The validation server to use to validate the transaction with
	 *
	 * @var url (string)
	 */
	private $mValidationServer;

	/**
	 * Token for the session.
	 * @var string
	 */
	private $mToken = null;

	/**
	 * The callback to call when an error occurs (takes an error code and an optional string)
	 *
	 * @var callback
	 */
	private $mErrorCallback = null;

	/**
	 * Initializes a transaction.
	 *
	 * @param lmTextChunk $chunk - The text chunk, with data to initialize; see derived classes for more info
	 * @param string $tokenkey - The key to send with the token request to the server, that it can encrypt messages with
	 */
	abstract public function Initialize(lmTextChunk $treq, $tokenkey);

	/** !EXPORT
	 * Returns the data that a website should store after initializing a transaction, so that they can validate with it later on.
	 *
	 * This data MUST NOT BE STORED IN A COOKIE OR FORM DATA OR ANY OTHER PUBLIC MEDIUM. *
	 * It should be stored in the session or database.  If you want to store it in a cookie or *
	 * hidden form field use the method GetPersistentDataForPublicStorage().
	 *
	 * @return string
	 */
	public function GetPersistentData()
	{
		$this->CheckSocketRead();

		$chunk = new lmTextChunk("PDATA");
		$chunk->AddChunk("SKEY", $this->mSessionKey);
		$chunk->AddChunk("TOKEN", $this->getToken());
		$chunk->AddChunk("VSERV", $this->getValidationServer());
		$chunk->AddChunk("DSERV", $this->getDataServer());
		$chunk->AddChunk("FIELDS2", $this->getResponseFieldData());
		$chunk->AddChunk("EREPORT", Leap::GetReportingMode());
		return $chunk->Export();
	}

	/** !EXPORT
	 * Returns the data that a website should store after initializing a transaction, so that they can validate with it later on.
	 *
	 * This data CAN be stored publicly.  Only use this is you don't have suitable access to a session or database.  The *
	 * preferred method is to store the data inside the session or database.
	 *
	 * Prefer to use: GetPersistentData() and store your data in a session or database.
	 *
	 * @param string $unique_id - A unique ID or Session ID.  Possibly a NONCE
	 * @return string
	 */
	public function GetPersistentDataForPublicStorage($unique_id)
	{
		$clientkey = Leap::GetClientKey();

		$chunk = new lmTextChunk('PDPUBLIC');
		$chunk->AddChunk('TIME', time());
		$chunk->AddChunk('PUID', md5($unique_id).'-'.lmHelper::GenerateWebUserID());
		$chunk->AddChunk('PSDATA', $this->GetPersistentData());
		$chunk->AddChunk("EREPORT", Leap::GetReportingMode());

		$enciphered = lmSymmetricMessage::EncipherMessage($clientkey->GetChunk('SKEY'), $chunk->Export(), $clientkey->GetChunk('CID'), $clientkey->GetChunk('KID'));

		return $enciphered;
	}


	/** !EXPORT
	 * Gets a chunk of HTML code that has a list of <script type="text/javascript" src="myscript.js"></script> blocks
	 *
	 * @return string
	 */
	abstract public function GetLinks();

	/** !EXPORT
	 * Gets the HTML code that needs to be embedded in a website.
	 *
	 * @param $position - How you want the player positioned.  ('left', 'center', 'right')
	 * @return string
	 */
	abstract public function GetHTML($position='left');

	/** !EXPORT
	 * Gets the javascript code to run the leap stuff.
	 *
	 * Should call it inline, or in the onLoad function for the document You should be able to insert the javascript code directly into a function.
	 * It will be a list of calls, like: callLeapFunction1(); callLeapFunction2();
	 *
	 * So if you're not going to embed it inside javascript of your own, you'll have to wrap it in a <script type="text/javascript"></script> block
	 *
	 * @param boolean $isFlashTransparent - true if you want to set the wmode of the Flash swf to transparent
	 * @param boolean $setFocusToAnswerBox - true if you want the text entry box on the NuCaptcha player to be focused once it's loaded
	 * @param string $position - One of Leap::POSITION_LEFT, Leap::POSITION_RIGHT or Leap::POSITION_CENTER. Default is LEFT.
	 * @return string
	 */
	abstract public function GetJavascript(
		$isFlashTransparent = false,
		$setFocusToAnswerBox = false,
		$position = Leap::POSITION_LEFT
	);


	/** !EXPORT
	 * Gets the javascript code to reinitialize the players with a new token.
	 *
	 * Used to do ajax submits, without having to do submit on a form.
	 * Returns a javascript block of code that can be eval'd.
	 *
	 * @param boolean $isFlashTransparent - true if you want to set the wmode of the Flash swf to transparent
	 * @param boolean $setFocusToAnswerBox - true if you want the text entry box on the NuCaptcha player to be focused once it's loaded
	 * @param string $position - One of Leap::POSITION_LEFT, Leap::POSITION_RIGHT or Leap::POSITION_CENTER. Default is LEFT.
	 * @return string
	 */
	abstract public function GetJavascriptToReinitialize(
			$isFlashTransparent = false,
			$setFocusToAnswerBox = false,
			$position = Leap::POSITION_LEFT
	);

	/** !EXPORT
	 * Gets the json object (as a string) to send (in javascript) to call the reinitialize function.
	 *
	 * To get the reinitialize function name, call GetJavascriptReinitializeFunctionName.
	 * Used to do ajax submits, without having to do submit on a form.
	 * Returns a javascript (json) encoded object.
	 *
	 * You can send in extra items to embed in the JSON object returned. The key's of the $extraParameters
	 * variable will be used as the names of the items in the JSON object, and the values will be the values.
	 * Note that you have to properly escape strings. So you'd have to do the following:
	 *
	 * $t->GetJSONToReinitialize(array("aString"=>"\"some string data\""));
	 *
	 * If you don't properly escape the string, then when the JSON object is used (or eval'd) in Javascript, it won't parse properly.
	 *
	 * @param array $extraParameters - hash table of extra parameters to put in the JSON
	 * @param boolean $isFlashTransparent - true if you want to set the wmode of the Flash swf to transparent
	 * @param boolean $setFocusToAnswerBox - true if you want the text entry box on the NuCaptcha player to be focused once it's loaded
	 * @param string $position - One of Leap::POSITION_LEFT, Leap::POSITION_RIGHT or Leap::POSITION_CENTER. Default is LEFT.
	 * @return string
	 */
	abstract public function GetJSONToReinitialize(
			$extraParameters = null,
			$isFlashTransparent = false,
			$setFocusToAnswerBox = false,
			$position = Leap::POSITION_LEFT
	);


	/** !EXPORT
	 * Gets everything and can be embedded into the html page.
	 *
	 * Derived classes should override GetWidgetInternal, not this function. That way when new parameters are added, the derived classes won't have to be changed
	 *
	 * @param boolean $isFlashTransparent - true if you want to set the wmode of the Flash swf to transparent
	 * @param boolean $setFocusToAnswerBox - true if you want the text entry box on the NuCaptcha player to be focused once it's loaded
	 * @param string $position - One of Leap::POSITION_LEFT, Leap::POSITION_RIGHT or Leap::POSITION_CENTER. Default is LEFT.
	 * @param string $lang - deprecated, set language in InitializeTransaction instead.
	 * @param string $skin - CSS skin to use. Enterprise customers only.
	 * @param int $tabIndex - Tab index to use for answer input or null for none (default)
	 * @return string
	 */
	abstract public function GetWidget(
			$isFlashTransparent = false,
			$setFocusToAnswerBox = false,
			$position = Leap::POSITION_LEFT,
			$lang = Leap::LANGUAGE_ENGLISH,
			$skin='default',
			$tabIndex=null
	);

	/** !EXPORT
	 * Returns of the javascript function to call to reinitialize the leap player, using the json object returned from GetJSONToReinitialize().
	 *
	 * @return string
	 */
	abstract public function GetJavascriptReinitializeFunctionName();

	/** !EXPORT
	 * Returns a unique string ID for this transaction
	 *
	 * @return string
	 */
	abstract public function GetTransactionID();
	
	/**
	 * Process the TRES.
	 *
	 * @param lmTextChunkData
	 */
	abstract protected function decodeTRESChunk(lmTextChunkData $TRES);

	/*
	 * Code below this point handles socket communications
 	 */

	/**
	 * The token request message
	 *
	 * @var string
	 */
    private $mRequest = false;

	/**
	 * Indicates whether or not the socket has been read from yet.
	 *
	 * @var boolean
	 */
	private $mSocketRead = false;

	/**
	 * True if there was a failure
	 *
	 * @var boolean
	 */
	private $mFailed = false;

	/**
	 * Formatted HTML with error info
	 *
	 * @var string
	 */
	protected $mErrorInfo = 0;

	/**
	 * Error code, or false
	 *
	 * @var int or false
	 */
	protected $mErrorCode = false;

	/**
	 * Did the transaction fail?
	 *
	 * @return bool
	 */
	protected function transactionFailed()
	{
		return $this->mFailed;
	}

	/**
	 * Get the error info string
	 * @return string
	 */
	protected function getErrorInfo()
	{
		return $this->mErrorInfo;
	}

	/**
	 * Get the error code.
	 * @return int
	 */
	protected function getErrorCode()
	{
		return $this->mErrorCode;
	}

	const SEND_TREQ_ATTEMPTS = 4;
	
	/**
	 * Is this request pointing at our production servers?
	 */
	private function isProduction()
	{
		
		if(false === Leap::GetForceTokenServer()
		   && 'clusters.nucaptcha.com' == Leap::GetClusterRecord())
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	protected function sendTREQ(lmTextChunk $TREQ)
	{
		$this->mRequest = $this->EncipherTokenRequest($TREQ);

		

		if(true === $this->isProduction())
		{
			try
			{
				$this->sendTREQMasterRecord();
			}
			catch(Exception $e)
			{
				// connecting to master cluster record failed. Fall back
				// to the lmclusterpicker method.
				if(true === lmHelper::isDnsGetRecordSupported())
				{
					$this->sendTREQClusterPicker();
				}
				else
				{
					// re-throw the exception since we don't have support
					// for getDnsRecord
					throw $e;
				}
			}	
		}
		else
		{
			// forced a token server, use the old method.
			if(false === lmHelper::isDnsGetRecordSupported())
			{
				throw new Exception("dns_get_record() is not supported on this platform.");
			}

			$this->sendTREQClusterPicker();
		}
	}
	
	/**
	 * Use the lmClusterPicker to send the TREQ
	 * @param lmTextChunk $TREQ
	 */
	private function sendTREQClusterPicker()
	{
		// *** Create the Request, try again in the rare case of failure
		$success = false;
		$attempt = 1;
		while( false === $success && $attempt <= lmTransactionInterface::SEND_TREQ_ATTEMPTS )
		{
			$tokenServer = '';
			try
			{
				// ***
				// *** Post the request and return the token response
				// ***
				$tokenServer = lmClusterPicker::GetTokenServer();
				
				if( $attempt == lmTransactionInterface::SEND_TREQ_ATTEMPTS
				   && $this->isProduction() )
				{
					$tokenServer = LM_FALLBACK_TOKEN_SERVER;
				}
				
				$this->mSocket = new lmRPCLite($tokenServer, $this->mRequest);
				$this->mSocket->SendRequest();
				
				$success = true;
			}
			catch(Exception $e)
			{
				lmErrorReporter::SetErrorData('sendTREQ-Attempt-' . $attempt, $tokenServer);

				if( $attempt == lmTransactionInterface::SEND_TREQ_ATTEMPTS )
				{
					lmErrorReporter::SetErrorData('sendTREQ-Attempts', $attempt);
					throw $e;
				}
				else
				{
					// Pick a new cluster for the next attempt
					lmClusterPicker::ClearCluster();
					
					$attempt++;
				}
			}
		}
	}
	
	/**
	 * Try and connect using token.nucaptcha.com
	 */
	private function sendTREQMasterRecord()
	{
		// LEAP-1996 - for clients that don't support dns_get_record(), retry
		// a few times here
		$retryCount = 1;

		if(false === lmHelper::isDnsGetRecordSupported())
		{
			$retryCount = 3;
		}

		$lastException = null;

		for($i = 0; $i < $retryCount; $i++)
		{
			try
			{
				$this->mSocket = new lmRPCLite(Leap::GetMasterTokenServer(), $this->mRequest);
				$this->mSocket->SendRequest();
				// clear any exceptions from the last attempt
				$lastException = null;
			}
			catch(Exception $e)
			{
				$lastException = $e;
			}
		}

		if(null !== $lastException)
		{
			throw $lastException;
		}
	}

	/**
	 * EncipherTokenRequest:
	 * Packages up a token request chunk to send to the token server
	 *
	 * @param lmTextChunk $chunk	- The TREQ chunk, initialized already
	 */
	private function EncipherTokenRequest(lmTextChunk $chunk)
	{
		// *** Create the Request
		$key = lmHelper::GetClientKey();
		return lmSymmetricMessage::EncipherMessage(
			$key->GetChunk("SKEY"),
			$chunk->Export(),
			$key->GetChunk("CID"),
			$key->GetChunk("KID")
		);
	}

	/**
	 * Make sure we've done our socket read.
	 */
	protected function CheckSocketRead()
	{
		if ( !$this->mSocketRead )
		{
			$this->ReadSocket();
		}
	}

	/**
	 * External method for calling CheckSocketRead but hides the internal naming.
	 * CheckSocketRead may have been reimplemented in child classes (such as leaptransactionerror).
	 */
	public function ForceConnectionCompletion()
	{
		$this->CheckSocketRead();
	}

	/**
	 * ReadSocket:
	 * Reads the async socket connected to the token server. Waits until the data is sent entirely before it reads.
	 * Which can result in sitting and spinning here for awhile.
	 */
    private function ReadSocket()
    {
        if ( $this->mSocketRead || $this->mFailed )
        {
            return;
        }

        try
        {
            $enctoken = $this->mSocket->GetResult();

            $chunk = $this->DecodeTRES($enctoken);

            $this->mSocketRead = true;
        }
        catch (Exception $e)
        {
			$ec = LMEC_UNKNOWN;
			if( method_exists($e, 'getCode') )
			{
				$ec = $e->getCode();
			}

			if( $ec != LMEC_PUBLISHER_DISABLED )
			{
				lmErrorReporter::ReportException($e, array('read-socket-failed' => true) );
			}

			if(null != $this->mErrorCallback)
			{
				$callback = ($this->mErrorCallback);
				$callback($ec, $e->getMessage());
			}

			$this->mFailed = true;
			$code = $ec;
			$message = $e->getMessage();
			$callstack = $e->getTraceAsString();
			$this->mErrorInfo = "Error code: $code<br/>Error Message: $message<br/>Stack:<br/>$callstack<br/>";
			$this->mErrorCode = $code;
        }
    }

	/**
	 * Decodes the token from the token response from the token server, and stores some data from it
	 *
	 * @return lmTextChunkData
	 */
    protected function DecodeTRES($enctoken)
    {
		$chunk = lmHelper::DecodeToken($enctoken, $this->mSessionKey);

		// allow subclasses to handle any chunks they are looking for.
		$this->DecodeTRESChunk($chunk);

		if(true === $chunk->ChunkExists('ANSW'))
		{
			$this->mAnswers = $chunk->GetChunk('ANSW');
		}

        // Store the general transaction data
	    $this->mToken					= $chunk->GetChunk("TOKEN");
	    $this->mValidationServer		= $chunk->GetChunk("VSERV");
	    $this->mDataServer				= $chunk->GetChunk("DSERV");

        $this->mResponseFieldData		= $chunk->GetChunk("FIELDS2");
		
        return $chunk;
	}

	/*
	 * A bunch of accessors below this point
	 */

	/**
	 * @return string
	 */
	public function getResponseFieldData()
	{
		return $this->mResponseFieldData;
	}

	/**
	 * Gets the URL to the data server.
	 *
	 * NOTE: not for public consumption. This is used for testing.
	 *
	 * @return string
	 */
	public function getDataServer()
	{
		return $this->mDataServer;
	}

	/**
	 * Gets the URL to the validation server.
	 *
	 * NOTE: not for public consumption. This is used for testing.
	 *
	 * @return string
	 */
	public function getValidationServer()
	{
		return $this->mValidationServer;
	}


	/**
	 * Gets the encrypted token (from the token response)
	 *
	 * NOTE: not for public consumption. This is used for testing.
	 *
	 * @return string
	 */
	public function GetToken()
	{
		$this->CheckSocketRead();

		return $this->mToken;
	}

	/**
	 * Returns an array of answers, if they were supplied by the server.
	 *
	 * Sending answers must be enabled on the Leap servers.
	 *
	 * NOTE: not for public consumption. This is used for testing.
	 *
	 * @return Array
	 */
    public function GetAnswers()
    {
        $this->CheckSocketRead();

        return $this->mAnswers;
    }

	/**
	 * Sets the error callback from the transactions.
	 *
	 * @param string $errorCallBack
	 */
	protected function setErrorCallback($errorCallBack)
	{
		$this->mErrorCallback = $errorCallBack;
	}

	/**
	 * Sets the session key.
	 *
	 * @param string $sessionKey
	 */
	protected function setSessionKey($sessionKey)
	{
		$this->mSessionKey = $sessionKey;
	}
}
