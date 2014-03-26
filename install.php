<?php
/**
 * CleanTalk SMF mod installation PHP code
 *
 * @version 1.01
 * @package Cleantalk
 * @subpackage SMF
 * @author CleanTalk (welcome@cleantalk.ru)
 * @copyright (C) 2013 Сleantalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

$hooks = array(
	'integrate_pre_include' => '$sourcedir/cleantalk/CleantalkMod.php',
	'integrate_register' => 'cleantalk_check_register',
	'integrate_general_mod_settings' => 'cleantalk_general_mod_settings',
);

$isInstalling = empty($context['uninstalling']);

// set integration hooks
foreach ($hooks as $hook => $function) {
	if ($isInstalling) {
		add_integration_function($hook, $function);
	} else {
		remove_integration_function($hook, $function);
	}
}

if ($isInstalling) {
	// Anti-Spam Verification captcha disable
	updateSettings(array('reg_verification' => '0'), true);
	updateSettings(array('cleantalk_api_key' => ''), false);
} else {
	// Anti-Spam Verification captcha
	updateSettings(array('reg_verification' => '1'), true);
}
