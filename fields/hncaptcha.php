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

class JFormFieldHnCaptcha extends JFormField
{
	protected $type = 'HnCaptcha';

	public function __construct($form = null){
		require_once(dirname(__FILE__).DS.'..'.DS.'include'.DS.'hncaptchalib.php');
		$params = new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);
		$doc = JFactory::getDocument();

		$theme 		= $params->get('theme', 'clean');
		$lang 		= $params->get('lang', 'en');
		$tabindex 	= $params->get('tabindex', 0);


		parent::__construct($form);
	}

	protected function getInput(){
		error_log("JFormFieldHnCaptcha:getInput()");
		
		$lang = JFactory::getLanguage();
		
		
		$CAPTCHA_INIT = array (
			'tempfolder' => '', 
			'TTF_folder' => dirname(__FILE__).DS.'..'.DS.'fonts'.DS, 
			'TTF_RANGE' => explode(',',$params->get('hncaptcha_TTF_RANGE')), 
			'chars' => $params->get('hncaptcha_chars'), 
			'minsize'=>$params->get('hncaptcha_minsize'), 
			'maxsize'=>$params->get('hncaptcha_maxsize'),
			'maxrotation'=>$params->get('hncaptcha_maxrotation'), 
			'noise'=>$params->get('hncaptcha_noise'),
			'websafecolors'=>$params->get('hncaptcha_websafecolors'), 
			'refreshlink'=>$params->get('hncaptcha_refreshlink'), 
			'lang'=>'', //$lang->getDefault(),
			'maxtry'=>$params->get('hncaptcha_maxtry'), 
			'badguys_url'=>$params->get('hncaptcha_badguys_url'), 
			'secretstring,'=>$params->get('hncaptcha_secretstring'), 
			'secretposition'=>$params->get('hncaptcha_secretposition'), 
			'debug'=>$params->get('hncaptcha_debug'),
			'site_tags0' => $params->get('siteTagsLine0'),
			'site_tags1' => $params->get('siteTagsLine1'),
			'tag_pos' => $params->get('hncaptcha_tag_pos'),
			'watermarkAntiFreePornAttack' => $params->get('hncaptcha_watermarkAntiFreePornAttack'),
			'cw_defaultRGBRedBackgroungColor'=>$params->get('hncaptcha_cw_defaultRGBRedBackgroungColor'),
			'cw_defaultRGBGreenBackgroungColor'=>$params->get('hncaptcha_cw_defaultRGBGreenBackgroungColor'),
			'cw_defaultRGBBlueBackgroungColor'=>$params->get('hncaptcha_cw_defaultRGBBlueBackgroungColor'),
			'cw_useRandomBackgroungColor'=>$params->get('hncaptcha_cw_useRandomBackgroungColor'),
			'cw_minRGBBackgroungColor'=>$params->get('hncaptcha_cw_minRGBBackgroungColor'),
			'cw_maxRGBBackgroungColor'=>$params->get('hncaptcha_cw_maxRGBBackgroungColor')
		);
		
		

		$captcha = & new hn_captcha($CAPTCHA_INIT);
		
		$session =& JFactory::getSession();
		//Ive add accessor on private properties, it is bad bu HNCaptcha is too monolithic:
		// it is mixing model, view and controller in one class
		$session->set('hncaptcha_publicKey',$captcha->getPublicKey());
		$session->set('hncaptcha_key',$captcha->getKey());
		$session->set('hncaptcha_privateKey',$captcha->getPrivateKey());
		
		
		//$captcha->make_captcha();
		
		return "<img src='".$captcha->make_captcha(); 
	}
}