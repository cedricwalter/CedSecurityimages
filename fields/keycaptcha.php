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

class JFormFieldKeyCaptcha extends JFormField
{
	protected $type = 'KeyCaptcha';

	public function __construct($form = null){
		parent::__construct($form);
	}
	
	protected function getInput(){
        require_once(dirname(__FILE__).DS.'..'.DS.'include'.DS.'keycaptchalib.php');
		$params = new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);
		$kc_o =  new SecurityImagesKeyCaptcha($params->get('keycaptcha_privateKey'), $params->get('keycaptcha_userId'));
		return $kc_o->render_js();
	}
}