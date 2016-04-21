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

global $db_connection, $smcFunc;

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
	db_extend('packages');

	$smcFunc['db_drop_table']('{db_prefix}cleantalk_sfw');

	$columns = array(
	    array(
	    'name' => 'network',
	    'type' => 'int',
	    'size' => 11,
	    'unsigned' => true,
	    ),
	    array(
	    'name' => 'mask',
	    'type' => 'int',
	    'size' => 11,
	    'unsigned' => true,
	    ),
	);
	$indexes = array(
	    array(
	    'type' => 'primary',
	    'columns' => array('network', 'mask')
	    ),
	);
	$smcFunc['db_create_table']('{db_prefix}cleantalk_sfw', $columns, $indexes, array(), 'update_remove');

	$smcFunc['db_add_column'](
	    '{db_prefix}members',
	    array(
		'name' => 'ct_marked',
		'type' => 'int',
		'default' => 0
	    )
	);
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
	db_extend('packages');
    	$smcFunc['db_drop_table']('{db_prefix}cleantalk_sfw');
	$smcFunc['db_remove_column']('{db_prefix}members', 'ct_marked', array(), '');
    }
}
