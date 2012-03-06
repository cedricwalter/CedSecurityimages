<?php
/**
 * @package   NuCaptcha PHP clientlib
 * @author    <support@nucaptcha.com> Leap Marketing Technologies Inc
 * @license   LGPL License 2.1 (see included license.txt)
 * @link      http://www.nucaptcha.com/api/php
 */

// we only want to redefine the client version of this class if we haven't already defined the non-client version
if(defined("LMEC_TESTCODE"))
{
	return;
}

define("LMEC_TESTCODE", 9999);

// Generic (1-999)
define ("LMEC_RESERVED0", 0);			// Reserve common value to avoid problems
define ("LMEC_RESERVED1", 1);

define("LMEC_OK", 10);
define("LMEC_ERROR", 11);
define("LMEC_UNKNOWN", 12);
define("LMEC_UNDEFINED", 13);
define("LMEC_INVALIDDATA", 14);
define("LMEC_INVALIDTYPE", 15);
define("LMEC_INVALIDPOST", 16);		// Post parameters are wrong
define("LMEC_ERROROPENINGFILE", 17);
define("LMEC_NOTSUPPORTED", 18);
define("LMEC_FILEERROR", 19);
define("LMEC_FORKERROR", 20);
define("LMEC_DUPLICATE", 21);
define("LMEC_OUTOFRANGE", 22);
define("LMEC_TEST", 23); // For testing only


// Token Server Response (1000-1099)
define("LMEC_INVALIDTREQTYPE", 1000);	// The Token Request Type is not valid
define("LMEC_NOBUCKETS", 1001);			// No available buckets
define("LMEC_PUBLISHER_DISABLED", 1002);

// Data Server Response (1100-1199)

// Validation Server Response (1200-1299)
define("LMEC_CORRECT", 1200);			// Correct Response
define("LMEC_WRONG", 1201);				// Wrong Response
define("LMEC_EMPTY", 1202);				// No Response
define("LMEC_INVALIDTOKENTYPE", 1203);	// The token wasn't good
define("LMEC_INVALIDVREQTYPE", 1204);	// The Valiation Request Type is not valid
define("LMEC_TOKENREPLAY", 1205);

// Leap Marketing Client Library (PHP) (1300-1399)
define("LMEC_NOTRANSACTION", 1300);		// No Transaction.  InitializeTransaction not called
define("LMEC_INVALIDTRES", 1301);		// The Token Response was invalid
define("LMEC_INVALIDDRES", 1302);		// The Data Response was invalid
define("LMEC_INVALIDVRES", 1303);		// The Validation Response was invalid
define("LMEC_INVALIDPERSISTENT", 1304);	// The persistent data was invalid
define("LMEC_INVALIDVERSION", 1305);    // invalid version used in encyphered message
define("LMEC_COULDNOTCONNECT", 1306);   // could not connect to a server
define("LMEC_SYMMETRICMESSAGEERROR", 1307); // problem encrypting or decrypting messages
define("LMEC_INVALIDIVLENGTH", 1308);    // invalid iv length used in encyphered message
define("LMEC_INVALIDBLOCKSIZE", 1309);    // invalid block size
define("LMEC_INVALIDKEY", 1310);        // invalid key
define("LMEC_INVALIDSENDER", 1311);        // invalid sender id
define("LMEC_INVALIDTEXTTYPE", 1312);        // invalid text chunk type enum
define("LMEC_INVALIDCONFIGFILE", 1313); 	// invalid config file on client machine
define("LMEC_MISMATCHRANDOMVALUES", 1314); 	// most likely as a result of a replay attack
define("LMEC_MISSINGPOSTDATA", 1315);		// most likely as a result of a replay attack
define("LMEC_CLIENTKEYNOTSET", 1316);		// client key not initialized


// Amazon Errors 2000-2099
define("LMEC_SDBERROR", 2000);

// *** Leap Library (PHP) (10000-19999)
// Communication (10000-10099)
define("LMEC_UNDEFINEDCHUNK", 10000);

// Event System (10100-10199)
define("LMEC_DUPLICATEEVENT", 10100);
define("LMEC_DUPLICATELISTENER", 10101);
define("LMEC_INVALIDEVENT", 10102);
define("LMEC_INVALIDLISTENER", 10103);
define("LMEC_UNKNOWNCHANNELTYPE", 10104);
define("LMEC_NOEVENT", 10105);
define("LMEC_DATANOTREAD", 10106);
define("LMEC_COULDNOTCREATEQUEUE", 10107);
define("LMEC_COULDNOTDELETEQUEUE", 10108);
define("LMEC_QUEUEDOESNOTEXIST", 10109);
define("LMEC_UNABLETOSENDEVENT", 10110);

// PDO and Database (10200-10299)
define("LMEC_PDOCONNECT", 10200);
define("LMEC_PDOPREPARE", 10201);

// QueueSub errors (10300-10399
define("LMEC_PRIORITYRANGE", 10300);

// Generic Communication (10400-10499)
define("LMEC_RSAERROR", 10400);
