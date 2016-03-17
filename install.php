<?php
/**
 * CleanTalk SMF mod installation PHP code
 *
 * @package Cleantalk
 * @subpackage SMF
 * @author CleanTalk (welcome@cleantalk.ru)
 * @copyright (C) 2014 Сleantalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

global $db_connection;

$hooks = array(
    'integrate_pre_include' => '$sourcedir/cleantalk/CleantalkMod.php',
    'integrate_register' => 'cleantalk_check_register',
    'integrate_general_mod_settings' => 'cleantalk_general_mod_settings',
    'integrate_load_theme' => 'cleantalk_load',
    'integrate_exit' => 'cleantalk_exit',
    'integrate_buffer' => 'cleantalk_buffer',
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
    updateSettings(array('posts_require_captcha' => '0'), true);

    $oldKey = isset($modSettings['cleantalk_api_key']) ? $modSettings['cleantalk_api_key'] : '';

    updateSettings(array('cleantalk_api_key' => $oldKey), false);
    updateSettings(array('cleantalk_first_post_checking' => '1'), false);
    updateSettings(array('cleantalk_logging' => '0'), false);
    //xdebug_break();
    if (!isset($db_connection) || $db_connection === false) {
	loadDatabase();
    }
    if (!isset($db_connection) || $db_connection === false) {
	trigger_error('CleanTalk install: you need to be connected to the database, please verify connection', E_USER_NOTICE);
    } else {
    	$sql='DROP TABLE IF EXISTS {db_prefix}cleantalk_sfw';
	$result = $smcFunc['db_query']('', $sql, Array());
	$sql='CREATE TABLE IF NOT EXISTS {db_prefix}cleantalk_sfw (
network int(11) unsigned NOT NULL,
mask int(11) unsigned NOT NULL,
INDEX (network, mask)
)';
	$result = $smcFunc['db_query']('', $sql, Array());
    }
} else {
    // Anti-Spam Verification captcha
    updateSettings(array('reg_verification' => '1'), true);
    //xdebug_break();
    if (!isset($db_connection) || $db_connection === false) {
	loadDatabase();
    }
    if (!isset($db_connection) || $db_connection === false) {
	trigger_error('CleanTalk uninstall: you need to be connected to the database, please verify connection', E_USER_NOTICE);
    } else {
    	$sql='DROP TABLE IF EXISTS {db_prefix}cleantalk_sfw';
	$result = $smcFunc['db_query']('', $sql, Array());
    }
}
