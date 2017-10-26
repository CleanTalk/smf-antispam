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

global $db_connection, $smcFunc, $modSettings;

$hooks = array(
    'integrate_pre_include'          => '$sourcedir/cleantalk/cleantalkMod.php',
	'integrate_pre_load'             => 'cleantalk_sfw_check',
    'integrate_register'             => 'cleantalk_check_register',
    'integrate_general_mod_settings' => 'cleantalk_general_mod_settings',
    'integrate_load_theme'           => 'cleantalk_load',
    'integrate_exit'                 => 'cleantalk_exit',
    'integrate_buffer'               => 'cleantalk_buffer',
);

$isInstalling = empty($context['uninstalling']);

// set integration hooks
foreach ($hooks as $hook => $function) {
    if($isInstalling){
        add_integration_function($hook, $function);
    }else{
        remove_integration_function($hook, $function);
    }
}

if ($isInstalling) {
		
    // Global settings. Anti-Spam Verification captcha disable
	updateSettings(array('reg_verification'              => '0'), true);
	updateSettings(array('posts_require_captcha'         => '0'), true);
	
	// Cleantalk's settings. Getting and set previous valuse, or set default valuse.
	updateSettings(array('cleantalk_api_key'             => isset($modSettings['cleantalk_api_key'])             ? $modSettings['cleantalk_api_key']             : ''),  false);
	updateSettings(array('cleantalk_first_post_checking' => isset($modSettings['cleantalk_first_post_checking']) ? $modSettings['cleantalk_first_post_checking'] : '1'), false);
	updateSettings(array('cleantalk_logging'             => isset($modSettings['cleantalk_logging'])             ? $modSettings['cleantalk_logging']             : '0'), false);
	updateSettings(array('cleantalk_tell_others'         => isset($modSettings['cleantalk_tell_others'])         ? $modSettings['cleantalk_tell_others']         : '1'), false);
	updateSettings(array('cleantalk_sfw'                 => isset($modSettings['cleantalk_sfw'])                 ? $modSettings['cleantalk_sfw']                 : '0'), false);
	
	// Cleantalk's secondary data                                                                                                                                  
	updateSettings(array('cleantalk_js_keys'             => isset($modSettings['cleantalk_js_keys'])             ? $modSettings['cleantalk_js_keys']             : ''),  false);
	
	// Accaunt status data
	updateSettings(array('cleantalk_api_key_is_ok'       => isset($modSettings['cleantalk_api_key_is_ok'])       ? $modSettings['cleantalk_api_key_is_ok']       : '0'), false);
	updateSettings(array('cleantalk_show_notice'         => isset($modSettings['cleantalk_show_notice'])         ? $modSettings['cleantalk_show_notice']         : '0'), false);
	updateSettings(array('cleantalk_renew'               => isset($modSettings['cleantalk_renew'])               ? $modSettings['cleantalk_renew']               : '0'), false);
	updateSettings(array('cleantalk_trial'               => isset($modSettings['cleantalk_trial'])               ? $modSettings['cleantalk_trial']               : '0'), false);
	updateSettings(array('cleantalk_user_token'          => isset($modSettings['cleantalk_user_token'])          ? $modSettings['cleantalk_user_token']          : ''),  false);
	updateSettings(array('cleantalk_spam_count'          => isset($modSettings['cleantalk_spam_count'])          ? $modSettings['cleantalk_spam_count']          : '0'), false);
	updateSettings(array('cleantalk_moderate_ip'         => isset($modSettings['cleantalk_moderate_ip'])         ? $modSettings['cleantalk_moderate_ip']         : '0'), false);
	updateSettings(array('cleantalk_show_review'         => isset($modSettings['cleantalk_show_review'])         ? $modSettings['cleantalk_show_review']         : '0'), false);
	updateSettings(array('cleantalk_ip_license'          => isset($modSettings['cleantalk_ip_license'])          ? $modSettings['cleantalk_ip_license']          : '0'), false);
	
	// Cron's settings
	updateSettings(array('cleantalk_sfw_last_update'     => isset($modSettings['cleantalk_sfw_last_update'])     ? $modSettings['cleantalk_sfw_last_update']     : time()+86400), false);
	updateSettings(array('cleantalk_sfw_last_logs_sent'  => isset($modSettings['cleantalk_sfw_last_logs_sent'])  ? $modSettings['cleantalk_sfw_last_logs_sent']  : time()+3600),  false);
	updateSettings(array('cleantalk_last_account_check'  => isset($modSettings['cleantalk_last_account_check'])  ? $modSettings['cleantalk_last_account_check']  : time()+86400), false);
	
    //xdebug_break();
    if (!isset($db_connection) || $db_connection === false) {
		loadDatabase();
    }
	
    if (!isset($db_connection) || $db_connection === false) {
		trigger_error('CleanTalk install: you need to be connected to the database, please verify connection', E_USER_NOTICE);
    }else{
		
		db_extend('packages');
		
	/* SFW data table */
		$smcFunc['db_drop_table']('{db_prefix}cleantalk_sfw');
		$smcFunc['db_query']('','CREATE TABLE {db_prefix}cleantalk_sfw (network INTEGER(11) UNSIGNED NOT NULL, mask INTEGER(11) UNSIGNED NOT NULL)',array());
		
	/* SFW logs table */
		$smcFunc['db_drop_table']('{db_prefix}cleantalk_sfw_logs');
		$columns = array(
			array(
				'name' => 'ip',
				'type' => 'varchar',
				'size' => 15
			),
			array(
				'name' => 'all_entries',
				'type' => 'int',
				'size' => 11,
				'default' => 0
			),
			array(
				'name' => 'blocked_entries',
				'type' => 'int',
				'size' => 11,
				'default' => 0
			),
			array(
				'name' => 'entries_timestamp',
				'type' => 'int',
				'size' => 11,
				'default' => 0
			),
		);
		$indexes = array(
			array(
				'type' => 'primary',
				'columns' => array('ip')
			),
		);
		$parameters = array();
		$smcFunc['db_create_table']('{db_prefix}cleantalk_sfw_logs', $columns, $indexes, $parameters, 'update_remove');
		
	/* Extending for users table */
		$smcFunc['db_add_column'](
			'{db_prefix}members',
			array(
				'name' => 'ct_marked',
				'type' => 'int',
				'default' => 0
			)
		);
		if (isset($modSettings['cleantalk_api_key']) && $modSettings['cleantalk_api_key'] != '' && isset($modSettings['cleantalk_sfw']) && $modSettings['cleantalk_sfw'] == 1)
		{
			if (!class_exists('CleantalkSFW'))
				require_once(dirname(__FILE__) . '/lib/CleantalkSFW.php');			
			$sfw = new CleantalkSFW;
			$sfw->sfw_update($modSettings['cleantalk_api_key']);
			unset($sfw);
			updateSettings(array('cleantalk_sfw_last_update' => time()+86400), false);			
		}	
    }
} else {
    // Anti-Spam Verification captcha
    updateSettings(array('reg_verification' => '1'), true);
    //xdebug_break();
	
    if (!isset($db_connection) || $db_connection === false){
		loadDatabase();
	}
	
    if (!isset($db_connection) || $db_connection === false){
		trigger_error('CleanTalk uninstall: you need to be connected to the database, please verify connection', E_USER_NOTICE);
    }else{
		db_extend('packages');
		$smcFunc['db_drop_table']('{db_prefix}cleantalk_sfw');
		$smcFunc['db_drop_table']('{db_prefix}cleantalk_sfw_logs');
		$smcFunc['db_remove_column']('{db_prefix}members', 'ct_marked', array(), '');
		$smcFunc['db_query']('',"DELETE FROM {db_prefix}settings WHERE variable LIKE '%cleantalk%'",array());
    }
}
