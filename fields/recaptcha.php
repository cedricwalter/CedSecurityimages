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

jimport('joomla.form.formfield');
jimport('joomla.html.parameter');

class JFormFieldReCaptcha extends JFormField
{
	protected $type = 'ReCaptcha';

	public function __construct($form = null){
		require_once(dirname(__FILE__).DS.'..'.DS.'include'.DS.'recaptchalib.php');
		$params = new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);
		$doc = JFactory::getDocument();
		
		$theme 		= $params->get('theme', 'clean');
		$lang 		= $params->get('lang', 'en');
		$tabindex 	= $params->get('tabindex', 0);
		
		$doc->addScriptDeclaration("
			var RecaptchaOptions = {
			   theme : '${theme}',
			   tabindex : ${tabindex},
			   lang : '${lang}'
			};
		");

		parent::__construct($form);
	}
	
	protected function getInput(){
		$params = new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);
		$publickey = $params->get('public_key');
  		return "<div>".recaptcha_get_html($publickey)."</div>";
	}
}