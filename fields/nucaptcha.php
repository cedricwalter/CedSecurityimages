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
jimport('joomla.session.session');

require_once(dirname(__FILE__) . DS . '..' . DS . 'include' . DS . 'nucaptcha' . DS . 'leapmarketingclient.php');

class JFormFieldNuCaptcha extends JFormField
{
    protected $type = 'NuCaptcha';

    protected function getInput()
    {
        $params = new JParameter(JPluginHelper::getPlugin('system', 'securityimages')->params);

        // Your ClientKey is supplied by Leap and can be downloaded from the publisher dashboard
        Leap::SetClientKey($params->get('nucaptcha_clientKey'));

        // The session is used in this example to store persistent data on the server
        //session_start();

        // initialize the transaction
        $t = Leap::InitializeTransaction();

        // check if the transaction initialization was successful
        if (LMEC_OK !== Leap::GetErrorCode()) {
            // log the error somewhere so we know it happened.
            // we don't have to worry about showing the error to the user since
            // Leap::ValidateOnError is enabled by default.
            error_log("Getting Transaction failed: " . Leap::GetErrorString());
        }

        // store the persistent data in the session for validation later
        // This should NEVER be sent to the client
        $options = array();
        $options['name'] = "nucaptcha";
        $session = JFactory::getSession($options);
        $session->set('leap',$t->GetPersistentData());

        // and get the actual player code
        return $t->GetWidget();
    }
}