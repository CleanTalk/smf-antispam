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

require_once(dirname(__FILE__) . '/cleantalk.class.php');

// define same CleanTalk options
define('CT_AGENT_VERSION', 'smf-140');
define('CT_SERVER_URL', 'http://moderate.cleantalk.org');


/**
 * CleanTalk integrate register hook
 * @param array $regOptions
 * @param array $theme_vars
 * @return void
 */
function cleantalk_check_register(&$regOptions, $theme_vars)
{
    global $language, $user_info, $modSettings;

    if ($regOptions['interface'] == 'admin') {
        return;
    }

    $ct = new Cleantalk();
    $ct->server_url = CT_SERVER_URL;

    $ct_request = new CleantalkRequest();
    $ct_request->auth_key = cleantalk_get_api_key();

    $ct_request->response_lang = 'en'; // SMF use any charset and language

    $ct_request->agent = CT_AGENT_VERSION;
    $ct_request->sender_email = isset($regOptions['email']) ? $regOptions['email'] : '';

    $ip = isset($regOptions['register_vars']['member_ip']) ? $regOptions['register_vars']['member_ip'] : $_SERVER['REMOTE_ADDR'];
    $ct_request->sender_ip = $ct->ct_session_ip($ip);

    $ct_request->sender_nickname = isset($regOptions['username']) ? $regOptions['username'] : '';

    $ct_request->submit_time = cleantalk_get_form_submit_time();

    $ct_request->js_on = cleantalk_is_valid_js() ? 1 : 0;

    $ct_request->sender_info = json_encode(
        array(
            'REFFERRER' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : null,
            'cms_lang' => substr($language, 0, 2),
            'USER_AGENT' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : null,
        )
    );

    /**
     * @var CleantalkResponse $ct_result CleanTalk API call result
     */
    $ct_result = $ct->isAllowUser($ct_request);

    if ($ct_result->inactive == 1) {
        // need admin approval

        cleantalk_log('need approval for "' . $regOptions['username'] . '"');

        $regOptions['register_vars']['is_activated'] = 3; // waiting for admin approval
        $regOptions['require'] = 'approval';

        if (!isset($modSettings['notify_new_registration']) || empty($modSettings['notify_new_registration'])) {
            // temporarly turn on notify for new registration
            $modSettings['notify_new_registration'] = 1;
        }

        // add Cleantalk message to email template
        $user_info['cleantalkmessage'] = $ct_result->comment;

        // temporarly turn on registration_method to approval_after
        $modSettings['registration_method'] = 2;
        return;
    }

    if ($ct_result->allow == 0) {
        // this is bot, stop registration
        cleantalk_log('deny registration' . strip_tags($ct_result->comment));
        fatal_error('CleanTalk: ' . strip_tags($ct_result->comment), false);
    } else {
        // all ok, only logging
        cleantalk_log('allow regisration for "' . $regOptions['username'] . '"');
    }
}

/**
 * Cleantalk check posts function
 * @param array $msgOptions
 * @param array $topicOptions
 * @param array $posterOptions
 */
function cleantalk_check_message(&$msgOptions, $topicOptions, $posterOptions)
{
    global $language, $user_info, $modSettings, $smcFunc;

    if (!$modSettings['cleantalk_first_post_checking']) {
        // post checking off
        return;
    } elseif (isset($user_info['posts']) && $user_info['posts'] > 0) {
        return;
    }

    $ct = new Cleantalk();
    $ct->server_url = CT_SERVER_URL;

    $ct_request = new CleantalkRequest();
    $ct_request->auth_key = cleantalk_get_api_key();

    $ct_request->response_lang = 'en'; // SMF use any charset and language

    $ct_request->agent = CT_AGENT_VERSION;
    $ct_request->sender_email = isset($posterOptions['email']) ? $posterOptions['email'] : '';

    $ip = isset($user_info['ip']) ? $user_info['ip'] : $_SERVER['REMOTE_ADDR'];
    $ct_request->sender_ip = $ct->ct_session_ip($ip);

    $ct_request->sender_nickname = isset($posterOptions['name']) ? $posterOptions['name'] : '';
    $ct_request->message = $msgOptions['body'];

    $ct_request->submit_time = cleantalk_get_form_submit_time();

    $ct_request->js_on = cleantalk_is_valid_js() ? 1 : 0;

    $ct_request->sender_info = json_encode(
        array(
            'REFFERRER' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : null,
            'cms_lang' => substr($language, 0, 2),
            'USER_AGENT' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : null,
        )
    );

    if (isset($topicOptions['id'])) {
        // disable query check for UNION operator
        $oldQueryCheck = isset($modSettings['disableQueryCheck']) ? $modSettings['disableQueryCheck'] : false;
        $modSettings['disableQueryCheck'] = true;

        // find first and last 5 messages
        $posts = $smcFunc['db_query'](
            '',
            'SELECT m.id_msg, m.body
                   FROM {db_prefix}messages AS m
                   JOIN {db_prefix}topics AS t ON t.id_first_msg=m.id_msg
                   WHERE t.id_topic = {int:id_topic}
                   UNION
                   (SELECT m.id_msg, m.body
                   FROM {db_prefix}messages AS m
                   WHERE m.id_topic = {int:id_topic2} AND m.approved=1
                   ORDER BY id_msg desc
                   limit 5)
                   ORDER BY id_msg',
            array(
                'id_topic' => $topicOptions['id'],
                'id_topic2' => $topicOptions['id'],
            )
        );
        $messages = array();
        while ($post = $smcFunc['db_fetch_assoc']($posts)) {
            $messages[] = $post['body'];
        }
        $smcFunc['db_free_result']($posts);
        $modSettings['disableQueryCheck'] = $oldQueryCheck;

        $ct_request->example = implode("\n", $messages);
    }

    /**
     * @var CleantalkResponse $ct_result CleanTalk API call result
     */
    $ct_result = $ct->isAllowMessage($ct_request);

    if ($ct_result->stop_queue == 1) {
        cleantalk_log('stop queue "' . $ct_result->comment . '"');
        fatal_error('CleanTalk: ' . strip_tags($ct_result->comment), false);

    } elseif ($ct_result->inactive == 1) {
        cleantalk_log('inactive message "' . $ct_result->comment . '"');

        if ($modSettings['postmod_active']) {
            // If post moderation active then set message not approved
            $msgOptions['approved'] = 0;
        }
        $msgOptions['cleantalk_check_message_result'] = $ct_result->comment;

    } else {
        // all ok, only logging
        cleantalk_log('allow message for "' . $posterOptions['name'] . '"');
    }
}

/**
 * After post created
 * @param array $msgOptions
 * @param array $topicOptions
 * @param array $posterOptions
 */
function cleantalk_after_create_topic($msgOptions, $topicOptions, $posterOptions)
{
    global $sourcedir, $scripturl;
    if (isset($msgOptions['cleantalk_check_message_result'])) {
        require_once($sourcedir . '/Subs-Admin.php');

        $link = $scripturl . '?topic=' . $topicOptions['id'] . '.msg' . $msgOptions['id'] . '#msg' . $msgOptions['id'];

        $message = $msgOptions['cleantalk_check_message_result'] . "\n\n" . $link;


        emailAdmins('send_email', array('EMAILSUBJECT' => '[Antispam for the board]', 'EMAILBODY' => "CleanTalk antispam failed: \n$message"));
    }
}

/**
 * Get CleanTalk hidden js code
 * @return string
 */
function cleantalk_get_checkjs_code()
{
    global $webmaster_email;

    return md5(cleantalk_get_api_key() . $webmaster_email);
}

/**
 * Get CleanTalk API KEY from SMF settings
 * @return string
 */
function cleantalk_get_api_key()
{
    global $modSettings;

    return isset($modSettings['cleantalk_api_key']) ? $modSettings['cleantalk_api_key'] : null;
}

/**
 * Add CleanTalk setting into admin panel
 * @param array $config_vars
 */
function cleantalk_general_mod_settings(&$config_vars)
{
    $config_vars[] = array('title', 'cleantalk_settings');
    $config_vars[] = array('text', 'cleantalk_api_key');
    $config_vars[] = array('check', 'cleantalk_first_post_checking');
    $config_vars[] = array('check', 'cleantalk_logging');
    $config_vars[] = array('desc', 'cleantalk_api_key_description');
}

/**
 * Return CleanTalk javascript verify code
 */
function cleantalk_print_js_input()
{
    $value = cleantalk_get_checkjs_code();

    return "<script type=\"text/javascript\">
        document.cookie = 'ct_checkjs=' + encodeURIComponent('$value') + ';path=/'
    </script>";
}

/**
 * Store form start time
 */
function cleantalk_store_form_start_time()
{
    $_SESSION['ct_form_start_time'] = time();
}

/**
 * Get form submit time
 * @return int|null
 */
function cleantalk_get_form_submit_time()
{
    return isset($_SESSION['ct_form_start_time']) ? time() - $_SESSION['ct_form_start_time'] : null;
}

/**
 * Logging message into SMF log
 * @param string $message
 */
function cleantalk_log($message)
{
    global $modSettings;
    if (array_key_exists('cleantalk_logging', $modSettings) && $modSettings['cleantalk_logging']) {
        log_error('CleanTalk: ' . $message, 'user');
    }
}

/**
 * Calling by hook integrate_load_theme
 */
function cleantalk_load()
{
    global $context, $user_info;

    if ($user_info['is_guest'] || $user_info['posts'] == 0) {
        cleantalk_store_form_start_time();
        if (!cleantalk_is_valid_js()) {
            $context ['html_headers'] .= cleantalk_print_js_input();
        }
    }
}

/**
 * Is Javascript enabled and valid
 * @return bool
 */
function cleantalk_is_valid_js()
{
    return array_key_exists('ct_checkjs', $_COOKIE) && $_COOKIE['ct_checkjs'] == cleantalk_get_checkjs_code();
}