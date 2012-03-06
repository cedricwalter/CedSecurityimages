<?php
/**
 * @package   NuCaptcha PHP clientlib
 * @author    <support@nucaptcha.com> Leap Marketing Technologies Inc
 * @license   LGPL License 2.1 (see included license.txt)
 * @link      http://www.nucaptcha.com/api/php
 */

// we only want to redefine the client version of this class if we haven't already defined the non-client version
if(class_exists("lmGlobalPerformance", false))
{
	return;
}

/**
 * Static access to an lmPeformance object
 */
class lmGlobalPerformance
{
    /**
     * Store the global performance object
     *
     * @var lmPerformance
     */
    private static $sPerformance = false;
    
    // no public constructor
    private function __construct() {}
    
    /**
     * Initialize the logger object
     *
     * @param string $loggername
     */
    public static function Initialize($loggername)
    {
	if(false == self::$sPerformance)
	{
	    self::$sPerformance = new lmPerformance($loggername);
	}
		
	return true;
    }
    
    public static function EnterSection ($section)
    {
	if(false != self::$sPerformance)
	{
	    return self::$sPerformance->enterSection($section);
	}
	
	return true;
    }
    
    public static function LeaveSection ($section)
    {
	if(false != self::$sPerformance)
	{
	    return self::$sPerformance->leaveSection($section);
	}
	
	return true;
    }
    
    /**
     * Get the underlying performance object.
     *
     * @return lmPerformance
     */
    public function GetPerformance()
    {
	return self::$sPerformace;
    }
}

