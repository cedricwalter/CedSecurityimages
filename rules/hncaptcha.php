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

class JFormRuleHnCaptcha extends JFormRule
{

	public function test(&$element, $value, $group = null, &$input = null, &$form = null)
	{
		$session = &JFactory::getSession();
		$publicKey = $session->get('publicKey');
		$hnkey = $session->get('hnkey');
		$privateKey = $session->get('privateKey');
		
		$enteredvalue	= JRequest::getVar('enteredvalue');

		$privateofPublic = $this->generatePrivate($publicKey, $hnkey);

		if (!empty ($publicKey) && !empty ($enteredvalue))
		{
			$usertry = strtolower($enteredvalue);
			$check = ($this->generatePrivate($publicKey, $hnkey));
			$res = ($usertry == $check) ? 'TRUE' : 'FALSE';
			$result = $res == 'TRUE' ? TRUE : FALSE;
			return $result;
		}
		return false;

	}

	function generatePrivate($public, $hnkey)
	{
		$params 	= new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);
		$key = substr(md5($hnkey . $public), 16 - $params->chars / 2, $params->chars);
		return $key;
	}



}