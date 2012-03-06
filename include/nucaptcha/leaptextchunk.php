<?php
/**
 * @package   NuCaptcha PHP clientlib
 * @author    <support@nucaptcha.com> Leap Marketing Technologies Inc
 * @license   LGPL License 2.1 (see included license.txt)
 * @link      http://www.nucaptcha.com/api/php
 */

// we only want to redefine the client version of this class if we haven't already defined the non-client version
if(!class_exists("lmTextChunk", false))
{
	/**
	 * Callback function to save out a string.  Doesn't do anything other
	 * than return the passed in string.
	 *
	 * @param string $string
	 * @return string
	 */
	function lmcallbackSaveString(&$string)
	{
		return $string;
	}

	function lmcallbackLoadString(&$string)
	{
		return $string;
	}

	/**
	 * Callback to convert an int to a string
	 *
	 * @param integer $int
	 * @return string
	 */
	function lmcallbackSaveInt($int)
	{
		return "".$int;
	}

	function lmcallbackLoadInt($int)
	{
		return $int;
	}

	/**
	 * Function to convert binary to a string.  It base64 encodes it.
	 *
	 * @param array/binary $bin
	 * @return base64 string
	 */
	function lmcallbackSaveBinary($bin)
	{
		return lmBase64::EncodeBinary($bin);
	}

	function lmcallbackLoadBinary($bin)
	{
		return lmBase64::DecodeBinary($bin);
	}

	function array_compare($needle, $haystack)
	{
		if (!is_array($needle) || !is_array($haystack) || (count($haystack) > count($needle)))
		{
			return false;
		}

		$count = 0;
		$result = false;
		foreach ($needle as $k => $v)
		{
			if (!isset($haystack[$k]))
			{
				return false;
			}
			if ($haystack[$k] != $v)
			{
				return false;
			}
		}
		return true;
	}

	/**
	 * Function to convert array to a string.  It will do so by creating a lmTextChunk
	 * and adding all the elements as chunks.
	 *
	 * @param array $array		- The data to add
	 * @param array $encoding	- Array of types to add for each data element
	 * @return string
	 */
	function lmcallbackSaveArray($array, $encoding)
	{
		if (count($array) != count($encoding))
		{
			throw new LeapException("Must have equal sizes for the data and the encoding format list", LMEC_INVALIDDATA);
		}

		// Create a new sub-chunk
		$chunk = new lmTextChunk("_");
		$chunk->AddChunk("_L", count($array));

		// Get the list of indexes to store
		$indices = array_keys($array);

		// See if we should skip the indices because they're indexed from 0..n
		$skip = true;
		$index = 0;
		foreach ($array as $key=>$value)
		{
			// If the index doesn't match the expected index of the array position
			if ($index++ != $key)
			{
				$skip = false;
				break;
			}
		}

		// See if all the keys match
		$skip |= array_compare(array_keys($encoding), $indices);

		// Add each data element
		$index = 0;
		foreach($encoding as $value)
		{
			// Generate the key
			$key = $index++;

			// Register and store the index name
			if (!$skip)
			{
				$indexkey = $key."K";
				$chunk->RegisterChunk($indexkey, "TEXT");
				$chunk->AddChunk($indexkey, array_shift($indices));
			}

			// Register and store the value name
			if ($skip)
			{
				$valuekey = $key;
			}
			else
			{
				$valuekey = $key."V";
			}

			$chunk->RegisterChunk($valuekey, $value);
			$chunk->AddChunk($valuekey, array_shift($array));
		}

		// Return the chunk
		return $chunk->Export();
	}

	function lmcallbackLoadArray($array, $encoding)
	{
		// Store the chunk types as we're creating temporary types and protects recursion
		$chunktypes = lmTextChunk::GetChunkTypes();

		// Predefine the chunk types
		$count = 0;
		foreach ($encoding as $type)
		{
			// Create the chunk names in case we stored the index names
			lmTextChunk::RegisterChunk($count."K", "TEXT");
			lmTextChunk::RegisterChunk($count."V", $type);
			// Create the chunk names based on index
			lmTextChunk::RegisterChunk($count, $type);
			$count++;
		}

		// Decode the chunk
		$chunk = lmTextChunk::Decode($array, "_");
		$len = $chunk->GetChunk("_L");
		$out = array();

		if ($len != count($encoding))
		{
			throw new LeapException("Must have equal sizes for the data and the encoding format list", LMEC_INVALIDDATA);
		}

		// See if we've skipped the indexes.  If we have the "V" on the first value then we know we have indexes
		$skip = !$chunk->ChunkExists("0V");
		if ($skip)
		{
			// Get the list of indexes to store
			$indices = array_keys($encoding);
		}

		for ($i = 0; $i < $len; $i++)
		{
			if ($skip)
			{
				$out[$indices[$i]] = $chunk->GetChunk($i);
			}
			else
			{
				$out[$chunk->GetChunk($i."K")] = $chunk->GetChunk($i."V");
			}
		}

		// restore the chunk types
		lmTextChunk::SetChunkTypes($chunktypes);

		// return the array
		return $out;
	}
	
	function lmcallbackLoadDData($data)
	{
		return lmUrlCoding::decodeStructure($data);
	}
	
	function lmcallbackSaveDData($data)
	{
		return lmUrlCoding::encodeStructure($data);
	}

	/**
	 * Class:
	 * lmTextChunk
	 *
	 * Purpose:
	 * This class is inteded to read and write the basic text chunk file
	 * format.  It is based off the IFF chunk format.
	 *
	 * Format:
	 * Header - A header of the count of chunks, followed by a pipe.
	 * Chunks - A string chunk name, followed by the char size, followed by the data
	 *          all separated by pipes.
	 */
	class lmTextChunk
	{
		const LM_TEXTCHUNK_MAGIC_STRING = "LEAP";
		const LM_TEXTCHUNK_VERSION = 0;

		/**
		 * An array of the known chunk types.  Initialized to zero
		 *
		 * @var array
		 */
		private static	$m_ChunkTypes		= array();
		/**
		 * An array of the available encoding types.  Each type must have
		 * accompanying save/load callbacks
		 *
		 * @var array(string)
		 */
		private static	$m_EncodingTypes	= array("TEXT", "INT", "BIN", "ARRAY", "DDATA");
		/**
		 * An array of callbacks for saving various encoding types
		 *
		 * @var callback
		 */
		private static	$m_SaveCallbacks	= array(
			"TEXT"  => "lmcallbackSaveString",
			"INT"   => "lmcallbackSaveInt",
			"BIN"   => "lmcallbackSaveBinary",
			"ARRAY" => "lmcallbackSaveArray",
			"DDATA" => "lmcallbackSaveDData",
		);
		/**
		 * An array of callbacks for loading various encoding types
		 *
		 * @var callback
		 */
		private static	$m_LoadCallbacks	= array(
			"TEXT"  => "lmcallbackLoadString",
			"INT"   => "lmcallbackLoadInt",
			"BIN"   => "lmcallbackLoadBinary",
			"ARRAY" => "lmcallbackLoadArray",
			"DDATA" => "lmcallbackLoadDData",
		);
		
		/**
		 * The seperator character.
		 *
		 * @var unknown_type
		 */
		private static  $m_PIPE				= '|';
		/**
		 * The list of chunks.  Format limitation is that there can only be one
		 * chunk of each type.  This is the list of the chunks in the 'file' and
		 * the data that they contain.
		 *
		 * @var array
		 */
		private 		$m_Chunks			= array();

		/**
		 * GetChunkTypes:
		 * This will return the chunk types array
		 *
		 * @return array
		 */
		static public function GetChunkTypes()
		{
			return lmTextChunk::$m_ChunkTypes;
		}

		/**
		 * SetChunkTypes:
		 * This will set the chunk types array
		 *
		 * @param array $types
		 */
		static public function SetChunkTypes($types)
		{
			lmTextChunk::$m_ChunkTypes = $types;
		}

		/**
		 * ValidateChunkEncoding:
		 * This will ensure that it is valid to encode in this format
		 *
		 * @param string $encoding - format you wish to encode in
		 * @return bool - true if OK
		 */
		static private function ValidateChunkEncoding($encoding)
		{
			// If it's not an array, just return whether or not it exists
			if (!is_array($encoding))
			{
				return (false !== array_search($encoding, lmTextChunk::$m_EncodingTypes));
			}

			// For each chunk in the array, validate the type
			$error = false;
			foreach ($encoding as $e)
			{
				$error |= !lmTextChunk::ValidateChunkEncoding($e);
			}
			return !$error;
		}

		/**
		 * RegisterChunk:
		 * This will add a new chunk type to the list of available chunks.
		 *
		 * @param string $chunkname - the name of the chunk (how it is referenced)
		 * @param string $encoding - the method of encoding.  Text?  Binary?  etc.
		 * @return binary - true if success, false otherwise
		 */
		static public function RegisterChunk($chunkname, $encoding)
		{
			$chunkname = strtoupper($chunkname);

			// Check to see if it's a valid encoding type
			if (lmTextChunk::ValidateChunkEncoding($encoding))
			{
				// Add the chunk type
				lmTextChunk::$m_ChunkTypes[$chunkname] = $encoding;
				return true;
			}
			throw new LeapException("$encoding is not a valid encoding type for chunk (Adding $chunkname).", LMEC_INVALIDTYPE);
			return false;
		}

		/**
		 * RegisterStandardChunkTypes:
		 * This will register all of the standard chunk types.  The class initializes
		 * lazily.
		 *
		 * TODO: These should be pre-initialized in $m_ChunkTypes.
		 *
		 */
		static private function RegisterStandardChunkTypes()
		{
			// Ensure we only register once
			static $registered = false;
			if ($registered) return;
			$registered = true;

			// Standard Chunk Chunks
			lmTextChunk::RegisterChunk("ERROR", "TEXT");		// An error is being passed
			lmTextChunk::RegisterChunk("CERROR", "BIN");		// An encrypted error
			lmTextChunk::RegisterChunk("ECODE", "INT");			// Error Code
			lmTextChunk::RegisterChunk("ELINE", "INT");			// Error Line number
			lmTextChunk::RegisterChunk("EFILE", "INT");			// Error Filename
			lmTextChunk::RegisterChunk("EHFILE", "INT");		// Error Filename - Hashed
			lmTextChunk::RegisterChunk("TRACE", "TEXT");		// Stack Trace
			lmTextChunk::RegisterChunk("EMSG", "TEXT");			// Decoded Error Message

			lmTextChunk::RegisterChunk("TYPE", "TEXT");			// Package Type
			lmTextChunk::RegisterChunk("CID", "INT");			// Client ID
			lmTextChunk::RegisterChunk("KID", "INT");			// Key ID
			lmTextChunk::RegisterChunk("TIME", "INT");			// TimeStamp (unix32bit)
			lmTextChunk::RegisterChunk("IV", "BIN");			// Initialization Vector
			lmTextChunk::RegisterChunk("SKEY", "BIN");			// Symmetric Key
			lmTextChunk::RegisterChunk("SESID", "TEXT");		// Session ID
			lmTextChunk::RegisterChunk("_L", "INT");			// The length of the array

			lmTextChunk::RegisterChunk("PUB_VER", "INT");		// The Publisher Library Version

			// Token Request Chunks
			lmTextChunk::RegisterChunk("IP", "TEXT");			// Users IP Address
			lmTextChunk::RegisterChunk("XF", "TEXT");			// Users XForward from header
			lmTextChunk::RegisterChunk("USERDATA", "BIN");		// Custom User Information
			lmTextChunk::RegisterChunk("UA", "TEXT");			// User agent
			lmTextChunk::RegisterChunk("RU", "TEXT");			// request URI
			lmTextChunk::RegisterChunk("RF", "TEXT");			// referrer
			lmTextChunk::RegisterChunk('USESSL', 'INT');
			lmTextChunk::RegisterChunk("CAID", "TEXT");			// Campaign ID
			lmTextChunk::RegisterChunk("TEMPLATE", "INT");		// Which template to use
			lmTextChunk::RegisterChunk("PURPOSE", "TEXT");		// Captcha purpose string
			lmTextChunk::RegisterChunk("PLATFORM", "TEXT");		// The platform we're running in
			lmTextChunk::RegisterChunk('HINTS', 'TEXT');        // Hints about the request
			lmTextChunk::RegisterChunk('DEFAULTLANG', 'TEXT');  // Widget language
			lmTextChunk::RegisterChunk('VERSION', 'INT');		
			
			// Token Response Chunks
			lmTextChunk::RegisterChunk("TOKEN", "TEXT");		// The token
			lmTextChunk::RegisterChunk("VSERV", "TEXT");		// The Validation Server
			lmTextChunk::RegisterChunk("DSERV", "TEXT");		// The Data Server
			lmTextChunk::RegisterChunk("RSERV", "TEXT");		// The Resource Server
			lmTextChunk::RegisterChunk("HTML", "TEXT");			// The HTML to output
			lmTextChunk::RegisterChunk("LINKS", "TEXT");		// The links (css, javascript) to output
			// TRES v0
			lmTextChunk::RegisterChunk("FIELDS", "TEXT");		// The string array of POST fields to be queried for the response
			lmTextChunk::RegisterChunk("JSVALUES", "TEXT");		// The string array of value to be sent to the javascript
	
			// TRES v1
			lmTextChunk::RegisterChunk("FIELDS2", "DDATA");		// The string array of POST fields to be queried for the response
			lmTextChunk::RegisterChunk("JSVALUES2", "DDATA");		// The string array of value to be sent to the javascript
			lmTextChunk::RegisterChunk("ANSW", array("TEXT", "TEXT", "TEXT", "TEXT", "TEXT")); // The answer list

			// TRES v5
			lmTextChunk::RegisterChunk("EREPORT", "TEXT");		// CSV string of preferred error reporters
			lmTextChunk::RegisterChunk("DISABLED_REASON", "TEXT"); // Is this publisher disabled.  If so, why?

			// Validate Request Chunks
			lmTextChunk::RegisterChunk("HASH", "TEXT");			// The hash of the token request, used to look up the response in memcache d

			// Validate Response Chunks
			lmTextChunk::RegisterChunk("VALID", "INT");			// Was the response valid?  0 = no, 1 = yes, 2 = error

			// LEAP-950 TREQ v1
			lmTextChunk::RegisterChunk('CAMPAIGNID', 'TEXT');

			// PHP API CHUNKS
			lmTextChunk::RegisterChunk("PSDATA", "TEXT");		// The Persistent Storage Data
			lmTextChunk::RegisterChunk("PUID", "TEXT");			// Public Unique ID
		}

		/**
		 * Constructor.  This will register the various chunk types.
		 *
		 * @param string $type - What type of request is this?
		 */
		public function __construct($type)
		{
			lmTextChunk::RegisterStandardChunkTypes();
			$this->AddChunk("TYPE", $type);
		}

		/**
		 * AddChunk:
		 * This will store the contents of $data into the chunk of type $name.
		 * The $data should be in the format specified byt the chunk $name.
		 *
		 * @param string $name - the chunk type
		 * @param variable $data - the data to store in the chunk
		 */
		public function AddChunk($name, $data)
		{
			$name = strtoupper($name);

			// Find the chunk type to get its encoding
			if (array_key_exists($name, lmTextChunk::$m_ChunkTypes))
			{
				// Get the encoding format
				$encoding = lmTextChunk::$m_ChunkTypes[$name];

				// If we're trying to store an array
				if (is_array($data) && is_array($encoding))
				{
					// Call the save function callback
					$callback = lmTextChunk::$m_SaveCallbacks["ARRAY"];
					$this->m_Chunks[$name] = $callback($data, $encoding);
					return;
				}
				// Confused encoding, one isn't an array
				else if (
					// it's okay for one to be an array if it's a list
					(is_array($data) && !is_array($encoding)
						&& 'DDATA' != $encoding)
				)
				{
					throw new LeapException("Must be an array when encoding for an array", LMEC_INVALIDTYPE);
				}
				// Simple data type (not array)
				else
				{
					// Check for case of boolean - set to empty string
					if (is_bool($data)) $data = "";		// LEAP-106

					// Call the save function callback
					$callback = lmTextChunk::$m_SaveCallbacks[$encoding];
					$this->m_Chunks[$name] = $callback($data);
					return;
				}
			}
			else
			{
				throw new LeapException("Could not find chunk type: $name.", LMEC_UNDEFINEDCHUNK);
			}
		}

		/**
		 * HasChunk:
		 * Returns true if a TextChunk has a particular chunk as part of it's data
		 *
		 * @param string $name - the chunk type
		 * @return boolean
		 */
		public function HasChunk($name)
		{
			if (array_key_exists($name, $this->m_Chunks) && isset($this->m_Chunks[$name]))
			{
				return true;
			}

			return false;
		}

		/**
		 * Export:
		 * This will convert all of the chunks into a single text stream.
		 *
		 * @return string
		 */
		public function Export()
		{
			$msg = "";

			// insert the magic text
			$msg = self::LM_TEXTCHUNK_MAGIC_STRING;

			// insert the version number
			$msg .= lmTextChunk::$m_PIPE . self::LM_TEXTCHUNK_VERSION;

			// Output the count
			$msg .= lmTextChunk::$m_PIPE;
			$msg .= count($this->m_Chunks);

			// Go through each element
			foreach ($this->m_Chunks as $key => $value)
			{
				$msg .= lmTextChunk::$m_PIPE . $key . lmTextChunk::$m_PIPE . strlen($value) . lmTextChunk::$m_PIPE . $value;
			}

			return $msg;
		}

		/**
		 * Decode:
		 * This will decode an encoded lmTextChunk export string
		 *
		 * @param string $tchunk - result of lmTextChunk->Export()
		 * @param string $expectedtype - string of the type expected
		 * @return lmTextChunkData
		 */
		static public function Decode(&$tchunk, $expectedtype)
		{
			lmTextChunk::RegisterStandardChunkTypes();
			//echo "Decoding:<BR>$tchunk<BR><BR>";
			$ret = new lmTextChunkData();

			// check for some magic
			$test = self::LM_TEXTCHUNK_MAGIC_STRING;
			$magic = substr($tchunk, 0, strlen(self::LM_TEXTCHUNK_MAGIC_STRING));
			if ( $magic != self::LM_TEXTCHUNK_MAGIC_STRING )
			{
				error_log(var_export($tchunk,true));
				throw new LeapException("No magic code at the beginning of the text string! $magic. Magic define itself is: " . $test, LMEC_INVALIDDATA);
			}

			// skip past the magic text and the first pipe now
			$pos = strlen(self::LM_TEXTCHUNK_MAGIC_STRING) + 1;

			// get the version number
			$end		= strpos($tchunk, lmTextChunk::$m_PIPE, $pos);
			$version	= substr($tchunk, $pos, $end-$pos);
			$pos = $end+1;

			if ( $version < self::LM_TEXTCHUNK_VERSION )
			{
				//throw new LeapException("Invalid version number for the text data!", LMEC_INVALIDDATA);
			}

			// Get the number of chunks
			$end		= strpos($tchunk, lmTextChunk::$m_PIPE, $pos);
			$numchunks	= substr($tchunk, $pos, $end-$pos);
			if ( $numchunks <= 0 )
			{
				throw new LeapException("Only '$numchunks' found.  Must be >=1", LMEC_INVALIDDATA);
			}
			//echo "Found $numchunks chunks<BR>";

			// Initialize our start position to just past the first pipe
			$pos = $end+1;

			// Go through all the chunks
			for ($i = 0; $i < $numchunks; $i++)
			{
				// Decode the name
				$end 	= strpos($tchunk, lmTextChunk::$m_PIPE, $pos);
				$name 	= substr($tchunk, $pos, $end-$pos);
				$pos	= ($end + 1);

				// always make the name of the chunk upper case
				$name = strtoupper($name);

				// Decode the data size
				$end 	= strpos($tchunk, lmTextChunk::$m_PIPE, $pos);
				$datasize= substr($tchunk, $pos, $end-$pos);
				$pos 	= ($end + 1);

				// Decode the data
				$data	= substr($tchunk, $pos, $datasize);
				$pos	= ($pos + $datasize + 1);

				// check that it's in the encoding array
				// if it isn't, skip it
				if (array_key_exists($name, lmTextChunk::$m_ChunkTypes))
				{
					$encoding = lmTextChunk::$m_ChunkTypes[$name];
					if (false !== lmTextChunk::ValidateChunkEncoding($encoding))
					{
						// If dealing with an array
						if (is_array($encoding))
						{
							$callback = lmTextChunk::$m_LoadCallbacks["ARRAY"];
							$ret->AddChunk($name, $callback($data, $encoding));
						}
						// Simple data type
						else
						{
							$callback = lmTextChunk::$m_LoadCallbacks[$encoding];
							$ret->AddChunk($name, $callback($data));
						}
					}
				}

				//echo "Read '$name' of $datasize bytes as '$data'<BR>";
			}

			// Grab the first chunk type
			$type = false;
			try
			{
				$type = $ret->GetChunk("TYPE");
			}
			catch (LeapException $e)
			{			
				throw new LeapException("Chunk TYPE not known. - ".$e->getTrace(), LMEC_UNDEFINEDCHUNK);
			}

			if (($type != $expectedtype) && (0 != strcmp("*", $expectedtype)))
			{
				throw new LeapException("Incorrect Chunk Type.  Expecting: '$expectedtype' - Found: '$type'", LMEC_INVALIDTYPE);
			}

			// Return the created chunkdata object
			return $ret;
		}
	}

	/**
	 * lmTextChunkData class
	 *
	 * This object is used to store the decoded TextChunk string from lmTextChunk.
	 *
	 */
	class lmTextChunkData
	{
		/**
		 * Private array holding the chunk=>data key pair
		 *
		 * @var unknown_type
		 */
		private $m_data	= array();

		/**
		 * This will add a chunk to the data
		 *
		 * @param string $name
		 * @param object $value
		 */
		public function AddChunk($name, $value)
		{
			$name = strtoupper($name);
			$this->m_data[$name] = $value;
		}

		/**
		 * GetChunk:
		 * This will return the chunk associated with the passed in name
		 * Need the debug throw mechanism because LeapException calls GetChunk()
		 *
		 * @param string $name
		 * @return object
		 */
		public function GetChunk($name, $debugthrow=true)
		{
			$name = strtoupper($name);
			if (isset($this->m_data[$name]))
			{
				return $this->m_data[$name];
			}
			// If in debug throw an exception, otherwise try to recover
			if ($debugthrow)
			{

				$chunks = "(Available: ";
				$keys = array_keys($this->m_data);
				foreach ($keys as $key)
				{
					$chunks .= "$key, ";
				}
				// Check to see if any chunks were added
				if (count($keys) >= 1)
				{
					// If so, remove the final ", " and append the ")"
					$chunks = substr($chunks, 0, strlen($chunks)-2).")";
				}
				else
				{
					// No chunks, so just say so
					$chunks .= "No available chunks)";
				}

				throw new LeapException("Trying to access chunk: $name that doesn't exist. $chunks", LMEC_UNDEFINEDCHUNK);
			}
			return "";
		}

		/**
		 * ChunExists:
		 * This will return true if it exists, false otherwise
		 *
		 * @param string $name
		 * @return bool
		 */
		public function ChunkExists($name)
		{
			$name = strtoupper($name);
			return (isset($this->m_data[$name]));
		}

		/**
		 * This will print out all the chunks in the ChunkData
		 *
		 * @return string
		 */
		public function PrintChunks()
		{
			$out = "";
			foreach ($this->m_data as $name => $data)
			{
				if (is_array($data))
				{
					$data = print_r($data, true);
				}
				$out .= "$name => $data<BR>";
			}
			return $out;
		}
	}

}
