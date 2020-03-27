<?php
/**
 * CleanTalk SMF mod
 *
 * @package Cleantalk
 * @subpackage SMF
 * @author CleanTalk (welcome@cleantalk.ru)
 * @copyright (C) 2014 Сleantalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

use CleantalkAP\Variables\Post;

if (!defined('SMF')) {
    die('Hacking attempt...');
}

/**
 * Add CleanTalk mod admin area
 * @param $admin_areas
 */
function cleantalk_admin_area(&$admin_areas)
{
    global $txt;

    $admin_areas['config']['areas']['modsettings']['subsections']['cleantalk'] = array($txt['cleantalk_name']);
}

/**
 * Add CleanTalk mod admin action
 * @param $subActions
 */
function cleantalk_admin_action(&$subActions)
{
    $subActions['cleantalk'] = 'cleantalk_general_mod_settings';
}

/**
 * Add CleanTalk mod settings area
 * @param bool $return_config
 * @return array
 */
function cleantalk_general_mod_settings($return_config = false)
{
    global $user_info, $txt, $scripturl, $context, $boardurl, $smcFunc;

    $context['page_title'] = $txt['cleantalk_settings'];
    $context['post_url'] = $scripturl . '?action=admin;area=modsettings;save;sa=cleantalk';

    // Get a real name for the Newbie membergroup
    $request = $smcFunc['db_query']('', '
                SELECT group_name
                FROM {db_prefix}membergroups
                WHERE id_group = {int:id_group}
                LIMIT 1',
        array(
            'id_group' => 4,
        )
    );

    list ($newbie_group_name) = $smcFunc['db_fetch_row']($request);
    $smcFunc['db_free_result']($request);
    if (!(trim($newbie_group_name))) {
        $newbie_group_name = '#4'; // Show a group number for empty name
    }
    $txt['cleantalk_first_post_checking_postinput'] = str_replace('%GROUP%', $newbie_group_name,
        $txt['cleantalk_first_post_checking_postinput']);

    $config_vars = array(
        array('title', 'cleantalk_settings'),
        array('text', 'cleantalk_api_key'),
        array('check', 'cleantalk_check_registrations', 'subtext' => $txt['cleantalk_check_registrations']),
        array('check', 'cleantalk_first_post_checking', 'subtext' => $txt['cleantalk_first_post_checking_postinput']),
        array('check', 'cleantalk_check_personal_messages', 'subtext' => $txt['cleantalk_check_personal_messages_postinput']),
        array('check', 'cleantalk_automod', 'subtext' => $txt['cleantalk_automod_postinput']),
        array('check', 'cleantalk_logging', 'subtext' => sprintf($txt['cleantalk_logging_postinput'], $boardurl)),
        array('check', 'cleantalk_email_notifications', 'subtext' => $txt['cleantalk_email_notifications_postinput']),
        array('check', 'cleantalk_ccf_checking', 'subtext' => $txt['cleantalk_ccf_checking_postinput']),
        array('check', 'cleantalk_tell_others', 'subtext' => $txt['cleantalk_tell_others_postinput']),
        array('check', 'cleantalk_sfw', 'subtext' => $txt['cleantalk_sfw_postinput']),
        array('desc', 'cleantalk_api_key_description'),
        array('desc', 'cleantalk_check_users'),
    );

    if ($return_config) {
        return $config_vars;
    }
    if (count($_POST) || !empty($_GET['ctgetautokey']))
    {
        $key_is_valid = false;
        $key_is_ok = false;    
        // Getting key automatically
        if(!empty($_GET['ctgetautokey'])){
            
            $result = CleantalkHelper::api_method__get_api_key($user_info['email'], $_SERVER['SERVER_NAME'], 'smf');

            if (empty($result['error'])){
                            
                // Doing noticePaidTill(), sfw update and sfw send logs via cron
                $key_is_valid = true;
                $save_key = $result['auth_key'];
                
            }
        }
        $save_key = $key_is_valid ? $save_key : Post::get( 'cleantalk_api_key' );
        if(!$key_is_valid)
        {
            $result = CleantalkHelper::apbct_key_is_correct($save_key);
            $key_is_valid = ($result) ? true: false;
        }
        if ($key_is_valid)
        {
            $result = CleantalkHelper::api_method__notice_paid_till($save_key, preg_replace('/http[s]?:\/\//', '', $_SERVER['HTTP_HOST'], 1));
            
            if (empty($result['error'])){
            	
                if($result['valid']){
                	
                    $key_is_ok = true;
                    $settings_array = array(
                        'cleantalk_api_key'       => ($save_key) ? $save_key : '',
                        'cleantalk_show_notice'   => isset($result['show_notice']) ? $result['show_notice'] : '0',
                        'cleantalk_renew'         => isset($result['renew']) ? $result['renew'] : '0',
                        'cleantalk_trial'         => isset($result['trial']) ? $result['trial'] : '0',
                        'cleantalk_user_token'    => isset($result['user_token']) ? $result['user_token'] : '',
                        'cleantalk_spam_count'    => isset($result['spam_count']) ? $result['spam_count'] : '0',
                        'cleantalk_moderate_ip'   => isset($result['moderate_ip']) ? $result['moderate_ip'] : '0',
                        'cleantalk_moderate'      => isset($result['moderate']) ? $result['moderate'] : '0',
                        'cleantalk_show_review'   => isset($result['show_review']) ? $result['show_review'] : '0',
                        'cleantalk_service_id'    => isset($result['service_id']) ? $result['service_id'] : '0',
                        'cleantalk_ip_license'    => isset($result['ip_license']) ? $result['ip_license'] : '0',
                        'cleantalk_account_name_ob' => isset($result['account_name_ob']) ? $result['account_name_ob'] : '',
                        'cleantalk_last_account_check' => time(),
                    );
                    
                    if (Post::get( 'cleantalk_sfw' ) == 1){
                        $settings_array['cleantalk_sfw'] = '1';
                        $settings_array['cleantalk_sfw_last_update'] = time();
                        $settings_array['cleantalk_sfw_last_logs_sent'] = time();
                        $sfw = new CleantalkSFW;
                        $sfw->sfw_update($save_key);
                        $sfw->send_logs($save_key);
                    }
                }else{
                    // @ToDo have to handle errors!
                    // return array('error' => 'KEY_IS_NOT_VALID');
                }

            }else{
                // @ToDo have to handle errors!
                // return array('error' => $result);
            }
        }
        $settings_array['cleantalk_api_key_is_ok'] = ($key_is_ok) ? '1' : '0';
        updateSettings($settings_array, false);         
    }
    
    if (isset($_GET['save'])) {
        checkSession();
        saveDBSettings($config_vars);
        redirectexit('action=admin;area=modsettings;sa=cleantalk');
    }

    prepareDBSettingContext($config_vars);

}
