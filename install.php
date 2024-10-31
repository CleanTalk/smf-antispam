<?php
/**
 * CleanTalk SMF mod installation PHP code
 *
 * @package Cleantalk
 * @subpackage SMF
 * @author CleanTalk (welcome@cleantalk.org)
 * @copyright (C) 2014 Сleantalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

global $db_connection, $smcFunc, $modSettings, $context;

$hooks = array(
    'integrate_pre_include'          => '$sourcedir/cleantalk/cleantalkMod.php',
	'integrate_pre_load'             => 'cleantalk_sfw_check',
    'integrate_register'             => 'cleantalk_check_register',
    'integrate_load_theme'           => 'cleantalk_load',
    'integrate_exit'                 => 'cleantalk_exit',    
    'integrate_buffer'               => 'cleantalk_buffer',
    'integrate_admin_include'        => '$sourcedir/cleantalk/cleantalkModAdmin.php',
    'integrate_admin_areas'          => 'cleantalk_admin_area',
    'integrate_modify_modifications' => 'cleantalk_admin_action',
    'integrate_personal_message'	 => 'cleantalk_check_personal_messages'
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
	updateSettings(array('cleantalk_check_registrations' => isset($modSettings['cleantalk_check_registrations']) ? $modSettings['cleantalk_check_registrations'] : '1'),  false);
	updateSettings(array('cleantalk_first_post_checking' => isset($modSettings['cleantalk_first_post_checking']) ? $modSettings['cleantalk_first_post_checking'] : '1'), false);
	updateSettings(array('cleantalk_logging'             => isset($modSettings['cleantalk_logging'])             ? $modSettings['cleantalk_logging']             : '0'), false);
	updateSettings(array('cleantalk_tell_others'         => isset($modSettings['cleantalk_tell_others'])         ? $modSettings['cleantalk_tell_others']         : '1'), false);
	updateSettings(array('cleantalk_sfw'                 => isset($modSettings['cleantalk_sfw'])                 ? $modSettings['cleantalk_sfw']                 : '0'), false);
	updateSettings(array('cleantalk_email_notifications' => isset($modSettings['cleantalk_email_notifications']) ? $modSettings['cleantalk_email_notifications'] : '0'), false);
	updateSettings(array('cleantalk_ccf_checking' 		 => isset($modSettings['cleantalk_ccf_checking'])        ? $modSettings['cleantalk_ccf_checking']        : '0'), false);
    updateSettings(array('cleantalk_check_search_form' 	 => isset($modSettings['cleantalk_check_search_form'])   ? $modSettings['cleantalk_check_search_form']        : '1'), false);
    updateSettings(array('cleantalk_errors'              => isset($modSettings['cleantalk_errors'])              ? $modSettings['cleantalk_errors']              : ''),  false);
	
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
	updateSettings(array('cleantalk_moderate'        	 => isset($modSettings['cleantalk_moderate'])         	 ? $modSettings['cleantalk_moderate']         	 : '0'), false);
	updateSettings(array('cleantalk_show_review'         => isset($modSettings['cleantalk_show_review'])         ? $modSettings['cleantalk_show_review']         : '0'), false);
	updateSettings(array('cleantalk_service_id'          => isset($modSettings['cleantalk_service_id'])          ? $modSettings['cleantalk_service_id']          : '0'), false);
	updateSettings(array('cleantalk_ip_license'          => isset($modSettings['cleantalk_ip_license'])          ? $modSettings['cleantalk_ip_license']          : '0'), false);
	updateSettings(array('cleantalk_account_name_ob'     => isset($modSettings['cleantalk_account_name_ob'])     ? $modSettings['cleantalk_account_name_ob']     : '0'), false);

	// Cron's settings
	updateSettings(array('cleantalk_sfw_last_update'     => isset($modSettings['cleantalk_sfw_last_update'])     ? $modSettings['cleantalk_sfw_last_update']     : '0'), false);
	updateSettings(array('cleantalk_sfw_last_logs_sent'  => isset($modSettings['cleantalk_sfw_last_logs_sent'])  ? $modSettings['cleantalk_sfw_last_logs_sent']  : '0'),  false);
	updateSettings(array('cleantalk_last_account_check'  => isset($modSettings['cleantalk_last_account_check'])  ? $modSettings['cleantalk_last_account_check']  : '0'), false);
	updateSettings(array('cleantalk_remote_calls'  		 => isset($modSettings['cleantalk_remote_calls'])  		 ? $modSettings['cleantalk_remote_calls']  		 : 	json_encode(array('close_renew_banner' => array('last_call' => 0, 'cooldown' => 10), 'sfw_update' => array('last_call' => 0, 'cooldown' => 10), 'sfw_send_logs' => array('last_call' => 0, 'cooldown' => 10), 'sfw_update__write_base' => array('last_call' => 0, 'cooldown' => 0)))), false);
	updateSettings(array('cleantalk_cron' => isset($modSettings['cleantalk_cron']) ? $modSettings['cleantalk_cron'] : array()), false);
	updateSettings(array('firewall_updating_id' => isset($modSettings['firewall_updating_id']) ? $modSettings['firewall_updating_id'] : 0), false);
	updateSettings(array('firewall_updating_last_start' => isset($modSettings['firewall_updating_last_start']) ? $modSettings['firewall_updating_last_start'] : 0), false);
	updateSettings(array('firewall_update_percent' => isset($modSettings['firewall_update_percent']) ? $modSettings['firewall_update_percent'] : 0), false);
	
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
		$columns = array(
			array(
				'name' => 'id',
				'type' => 'int',
				'size' => 11,
				'auto' => true
			),
			array(
				'name' => 'network',
				'type' => 'int',
				'size' => 11,
				'unsigned' => true
			),
			array(
				'name' => 'mask',
				'type' => 'int',
				'size' => 11,
				'unsigned' => true
			),
			array(
				'name' => 'status',
				'type' => 'int',
				'size' => 1,
				'default' => 0
			)
		);
		$indexes = array(
			array(
				'type' => 'primary',
				'columns' => array('id')
			),
		);
		$parameters = array();
		$smcFunc['db_create_table']('{db_prefix}cleantalk_sfw', $columns, $indexes, $parameters, 'update_remove');
		
	/* SFW logs table */
		$smcFunc['db_drop_table']('{db_prefix}cleantalk_sfw_logs');
		$columns = array(
			array(
				'name' => 'id',
				'type' => 'varchar',
				'size' => 40
			),
			array(
				'name' => 'ip',
				'type' => 'varchar',
				'size' => 15
			),
			array(
				'name' => 'status',
				'type' => 'varchar',
				'size' => 50
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
			array(
				'name' => 'ua_id',
				'type' => 'int',
				'size' => 11,
				'null' => true,
				'default' => null
			),
			array(
				'name' => 'ua_name',
				'type' => 'varchar',
				'size' => 1024
			),
		);
		$indexes = array(
			array(
				'type' => 'primary',
				'columns' => array('id')
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
		$smcFunc['db_query']('',"DELETE FROM {db_prefix}settings WHERE variable LIKE '%cleantalk%' OR variable LIKE '%firewall_upd%'",array());
    }
}
