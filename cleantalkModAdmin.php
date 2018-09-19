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
    global $txt, $scripturl, $context, $boardurl;

    $context['page_title'] = $txt['cleantalk_settings'];
    $context['post_url'] = $scripturl . '?action=admin;area=modsettings;save;sa=cleantalk';

    $config_vars = array(
        array('title', 'cleantalk_settings'),
        array('text', 'cleantalk_api_key'),
        array('check', 'cleantalk_first_post_checking', 'subtext' => $txt['cleantalk_first_post_checking_postinput']),
        array('check', 'cleantalk_logging', 'subtext' => sprintf($txt['cleantalk_logging_postinput'], $boardurl)),
        array('check', 'cleantalk_email_notifications', 'subtext' => $txt['cleantalk_email_notifications']),
        array('check', 'cleantalk_ccf_checking', 'subtext' => $txt['cleantalk_ccf_checking']),
        array('check', 'cleantalk_tell_others', 'subtext' => $txt['cleantalk_tell_others_postinput']),
        array('check', 'cleantalk_sfw', 'subtext' => $txt['cleantalk_sfw_postinput']),
        array('desc', 'cleantalk_api_key_description'),
        array('desc', 'cleantalk_check_users'),
    );

    if ($return_config) {
        return $config_vars;
    }

    if (isset($_GET['save'])) {
        checkSession();
        saveDBSettings($config_vars);
        redirectexit('action=admin;area=modsettings;sa=cleantalk');
    }

    prepareDBSettingContext($config_vars);
}
