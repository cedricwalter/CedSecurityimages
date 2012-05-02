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
jimport('joomla.error.log');

class plgSystemSecurityImages extends JPlugin
{

    var $logger = null;
    var $debug = false;

    static $activeForms = array('com_users.registration',
        'com_users.login',
        'com_users.reset_request',
        'com_users.remind',
        'com_users.profile',
        'com_contact.contact');


    function __construct(&$subject, $config)
    {
        parent::__construct($subject, $config);
        $this->debug = $this->get('debug', '0');
        $this->logger = JLog::getInstance('plg_system_securityimages.php', array('format' => "{DATE}\t{TIME}\t{COMMENT}"));
    }

    function debug($message)
    {
        if ($this->debug) {
            $this->logger->addEntry(array('comment' => "Plugin plg_system_securityimages is active"));
        }
    }

    /**
     *
     * Enter description here ...
     * @param unknown_type $form
     * @param unknown_type $data
     */
    function onContentPrepareForm($form, $data)
    {
        $app = JFactory::getApplication();
        if ($app->getName() != 'site') {
            return true;
        }

        $this->debug("Form name <" . $form->getName() . ">");

        if (!($form instanceof JForm)) {
            $this->_subject->setError('JERROR_NOT_A_FORM');
            $this->debug("Form name <" . $form->getName() . "> not a JForm yet in Joomla! core");
            return false;
        }
        $this->loadLanguage();
        JForm::addFieldPath(dirname(__FILE__) . '/fields');
        JForm::addFormPath(dirname(__FILE__) . '/forms');

        if ($this->params->get('override', '1') == false &&
            in_array($form->getName(), plgSystemSecurityImages::$activeForms) == false
        ) {
            $this->debug("Form name <" . $form->getName() . "> Not in the list of active forms");
            return true;
        }

        if ($this->get('override') ||
            ($form->getName() == "com_users.registration") && $this->params->get('register') ||
            ($form->getName() == 'com_users.login') && $this->params->get('login', '1') ||
            ($form->getName() == 'com_users.reset_request') && $this->params->get('reset', '1') ||
            ($form->getName() == 'com_users.remind') && $this->params->get('remind', '1') ||
            ($form->getName() == 'com_users.profile') && $this->params->get('contact', '1') ||
            ($form->getName() == 'com_contact.contact') && $this->params->get('contact', '1')
        ) {
            $this->debug("Add now securityimages to the Form name <" . $form->getName() . ">");
            $params = new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);
            $form->loadFile($params->get('captchaType', 'nucaptcha'), false);
        }
        return true;
    }
}