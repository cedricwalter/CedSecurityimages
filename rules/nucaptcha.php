<?php
/**
 * @version        SecurityImages
 * @package
 * @copyright    Copyright (C) 2004-2012 Cedric Walter. All rights reserved.
 * @copyright    www.cedricwalter.com / www.waltercedric.com
 *
 * @license        GNU/GPL, see LICENSE.php
 *
 * SecurityImages is free software. This version may have been modified pursuant
 * to the GNU General Public License, and as distributed it includes or
 * is derivative of works licensed under the GNU General Public License or
 * other free or open source software licenses.
 * See COPYRIGHT.php for copyright notices and details.
 */

defined('_JEXEC') or die;

jimport('joomla.form.formrule');
jimport('joomla.html.parameter');
jimport('joomla.session.session');
require_once(dirname(__FILE__).DS.'..'.DS.'include'.DS.'nucaptcha'.DS.'leapmarketingclient.php');

class JFormRuleNuCaptcha extends JFormRule
{

	public function test(&$element, $value, $group = null, &$input = null, &$form = null)
	{
        $options = array();
        $options['name'] = "nucaptcha";
        $session = JFactory::getSession($options);
        $leap = $session->get('leap');

		// Check if the persistent data was stored, and if the user actually submitted an answer
		if(null != $leap && true === Leap::WasSubmitted())
		{
            $params = new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);

            // Your ClientKey is supplied by Leap and can be downloaded from the publisher dashboard
            Leap::SetClientKey($params->get('nucaptcha_clientKey'));

			// validate the transaction
			$valid = Leap::ValidateTransaction($leap);

			// check for error
			// by default, ValidateTransaction will return true on error
			if( Leap::GetErrorCode() != LMEC_CORRECT &&
			Leap::GetErrorCode() != LMEC_WRONG &&
			Leap::GetErrorCode() != LMEC_EMPTY )
			{
				// log the error somewhere so we know it happened
				error_log(
            'Error Code: ' . Leap::GetErrorCode() .
            ' Error Message: ' . Leap::GetErrorString()
				);
			}

			return $valid;
		}

		return false;
	}
}