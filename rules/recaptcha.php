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


class JFormRuleReCaptcha extends JFormRule
{

	public function test(&$element, $value, $group = null, &$input = null, &$form = null)
	{
        include(dirname(__FILE__).DS.'..'.DS.'include'.DS.'recaptchalib.php');
		$params 	= new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);
		$privatekey = $params->get('private_key');
		$addr		= JRequest::getVar('REMOTE_ADDR', null, 'server');
		$challenge	= JRequest::getVar('recaptcha_challenge_field');
		$response	= JRequest::getVar('recaptcha_response_field');
		$result 	= recaptcha_check_answer ($privatekey, $addr, $challenge, $response);
		return $result->is_valid;
	}
}