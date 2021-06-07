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

// Classes autoloader
require_once(dirname(__FILE__) . '/lib/autoload.php');

//Antispam classes
use Cleantalk\Antispam\Cleantalk;
use Cleantalk\Antispam\CleantalkRequest;
use Cleantalk\Antispam\CleantalkResponse;

//Common classes
use Cleantalk\Common\API as CleantalkAPI;
use Cleantalk\ApbctSMF\Helper as CleantalkHelper;
use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\ApbctSMF\RemoteCalls;
use Cleantalk\ApbctSMF\Cron;
use Cleantalk\ApbctSMF\DB;
use Cleantalk\Common\Variables\Post;
use Cleantalk\Common\Variables\Server;
use Cleantalk\Common\Firewall\Modules\SFW;

if (!defined('SMF')) {
    die('Hacking attempt...');
}

// Common CleanTalk options
define('CT_AGENT_VERSION', 'smf-234');
define('CT_SERVER_URL', 'http://moderate.cleantalk.org');
define('CT_DEBUG', false);
define('CT_REMOTE_CALL_SLEEP', 10);
define('APBCT_TBL_FIREWALL_DATA', 'cleantalk_sfw');      // Table with firewall data.
define('APBCT_TBL_FIREWALL_LOG',  'cleantalk_sfw_logs'); // Table with firewall logs.
define('APBCT_TBL_AC_LOG',        'cleantalk_ac_log');   // Table with firewall logs.
define('APBCT_TBL_AC_UA_BL',      'cleantalk_ua_bl');    // Table with User-Agents blacklist.
define('APBCT_TBL_SESSIONS',      'cleantalk_sessions'); // Table with session data.
define('APBCT_SPAMSCAN_LOGS',     'cleantalk_spamscan_logs'); // Table with session data.
define('APBCT_SELECT_LIMIT',      5000); // Select limit for logs.
define('APBCT_WRITE_LIMIT',       5000); // Write limit for firewall data.

function apbct_sfw_update($access_key = '') {
    if( empty( $access_key ) ){
        $access_key = cleantalk_get_api_key();
        if (empty($access_key)) {
            return false;
        }
    }     
    $firewall = new Firewall(
        $access_key,
        DB::getInstance(),
        APBCT_TBL_FIREWALL_LOG
    );
    $firewall->setSpecificHelper( new CleantalkHelper() );
    $fw_updater = $firewall->getUpdater( APBCT_TBL_FIREWALL_DATA );
    $fw_updater->update();
}

function apbct_sfw_send_logs($access_key = '') {
    if( empty( $access_key ) ){
        $access_key = cleantalk_get_api_key();
        if (empty($access_key)) {
            return false;
        }
    } 

    $firewall = new Firewall( $access_key, DB::getInstance(), APBCT_TBL_FIREWALL_LOG );
    $firewall->setSpecificHelper( new CleantalkHelper() );
    $result = $firewall->sendLogs();

    return true;
}
/**
 * CleanTalk SFW check
 * @return void
 */
function cleantalk_sfw_check()
{
    global $modSettings, $language, $user_info;

    if (isset($user_info) && $user_info['is_admin'])
        return;

    // Remote calls
    if( RemoteCalls::check() ) {
        $rc = new RemoteCalls( cleantalk_get_api_key());
        $rc->perform();
    }
    $cron = new Cron();
    $cron_option = isset($modSettings[$cron->getCronOptionName()]) ? json_decode($modSettings[$cron->getCronOptionName()], true) : array();

    if (empty($cron_option)) {
        $cron->addTask( 'sfw_update', 'apbct_sfw_update', 86400, time() + 60 );
        $cron->addTask( 'sfw_send_logs', 'apbct_sfw_send_logs', 3600 );
    }
    $tasks_to_run = $cron->checkTasks(); // Check for current tasks. Drop tasks inner counters.

    if(
        ! empty( $tasks_to_run ) && // There is tasks to run
        ! RemoteCalls::check() && // Do not doing CRON in remote call action
        (
            ! defined( 'DOING_CRON' ) ||
            ( defined( 'DOING_CRON' ) && DOING_CRON !== true )
        )
    ){
        $cron_res = $cron->runTasks( $tasks_to_run );
        // Handle the $cron_res for errors here.
    }
    if (!empty($modSettings['cleantalk_api_key_is_ok']))
    {
        cleantalk_cookies_set();
        if(!empty($modSettings['cleantalk_sfw']) ){
            
            $firewall = new Firewall(
                cleantalk_get_api_key(),
                DB::getInstance(),
                APBCT_TBL_FIREWALL_LOG
            );

            $firewall->loadFwModule( new SFW(
                APBCT_TBL_FIREWALL_DATA,
                array(
                    'sfw_counter'   => 0,
                    'cookie_domain' => Server::get('HTTP_HOST'),
                    'set_cookies'    => 1,
                )
            ) );

            $firewall->run();
        }

        if (
            /* Check all post query */
            (
                !empty($modSettings['cleantalk_ccf_checking'])
                && $_SERVER['REQUEST_METHOD'] == 'POST'
                && strpos($_SERVER['REQUEST_URI'], 'action=admin') === false
                && strpos($_SERVER['REQUEST_URI'], 'action=register') === false
                && strpos($_SERVER['REQUEST_URI'], 'action=profile') === false
                && strpos($_SERVER['REQUEST_URI'], 'action=signup') === false
                && strpos($_SERVER['REQUEST_URI'], 'action=login') === false
                && strpos($_SERVER['REQUEST_URI'], 'action=post') === false
                && strpos($_SERVER['REQUEST_URI'], 'action=pm') === false
                && strpos($_SERVER['REQUEST_URI'], 'action=search') === false
            )
            /* Check search form */
            || (
                !empty($modSettings['cleantalk_check_search_form'])
                && $_SERVER['REQUEST_METHOD'] == 'POST'
                && strpos($_SERVER['REQUEST_URI'], 'action=search') !== false
            )
        ){
            
            $ct_temp_msg_data = cleantalkGetFields($_POST);
            $sender_email    = ($ct_temp_msg_data['email']    ? $ct_temp_msg_data['email']    : '');
            $sender_nickname = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
            $subject         = ($ct_temp_msg_data['subject']  ? $ct_temp_msg_data['subject']  : '');
            $contact_form    = ($ct_temp_msg_data['contact']  ? $ct_temp_msg_data['contact']  : true);
            $message         = ($ct_temp_msg_data['message']  ? $ct_temp_msg_data['message']  : array());   
            if ($subject != '')
                $message = array_merge(array('subject' => $subject), $message);
            $message = implode("\n", $message);  
            if ($message != '' || $sender_email != '')
            {
                $ct = new Cleantalk();
                $ct->server_url = CT_SERVER_URL;

                $ct_request = new CleantalkRequest();
                $ct_request->auth_key = cleantalk_get_api_key();

                $ct_request->response_lang = 'en'; // SMF use any charset and language

                $ct_request->agent = CT_AGENT_VERSION;
                $ct_request->sender_email = $sender_email;

                $ct_request->sender_ip = CleantalkHelper::ip__get(array('real'), false);
                $ct_request->x_forwarded_for = CleantalkHelper::ip__get(array('x_forwarded_for'), false);
                $ct_request->x_real_ip       = CleantalkHelper::ip__get(array('x_real_ip'), false);

                $ct_request->sender_nickname = $sender_nickname;
                $ct_request->message = $message;

                $ct_request->submit_time = cleantalk_get_form_submit_time();

                $ct_request->js_on = cleantalk_is_valid_js() ? 1 : 0;

                $ct_request->post_info = json_encode(array('post_url' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '', 'comment_type' => 'feedback_custom_contact_forms'));
                $ct_request->sender_info = json_encode(
                    array(
                        'REFFERRER'              => isset($_SERVER['HTTP_REFERER'])      ? $_SERVER['HTTP_REFERER']     : null,
                        'cms_lang'               => substr($language, 0, 2),                                            
                        'USER_AGENT'             => isset($_SERVER['HTTP_USER_AGENT'])   ? $_SERVER['HTTP_USER_AGENT']  : null,
                        'ct_options'             => cleantalk_get_ct_options($modSettings),
                        'js_timezone'            => isset($_COOKIE['ct_timezone'])       ? $_COOKIE['ct_timezone']      : null,
                        'mouse_cursor_positions' => isset($_COOKIE['ct_pointer_data'])   ? $_COOKIE['ct_pointer_data']  : null,
                        'key_press_timestamp'    => !empty($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : null,
                        'page_set_timestamp'     => !empty($_COOKIE['ct_ps_timestamp'])  ? $_COOKIE['ct_ps_timestamp']  : null,
                        'REFFERRER_PREVIOUS'     => isset($_COOKIE['ct_prev_referer'])? $_COOKIE['ct_prev_referer']: null,
                        'cookies_enabled'        => cleantalk_cookies_test(),
                        'js_keys'                => cleantalk_get_js_keys($modSettings)
                    )
                );
                $ct_result = $ct->isAllowMessage($ct_request);  
                if ($ct_result->allow == 0)
                {
                    $error_tpl=file_get_contents(dirname(__FILE__)."/error.html");
                    print str_replace('%ERROR_TEXT%',$ct_result->comment,$error_tpl);
                    die();                      
                }                             
            }           
        }
    }
}

//Recursevely gets data from array
function cleantalkGetFields($arr, $message=array(), $email = null, $nickname = array('nick' => '', 'first' => '', 'last' => ''), $subject = null, $contact = true, $prev_name = ''){
    
    //Skip request if fields exists
    $skip_params = array(
        'ipn_track_id',     // PayPal IPN #
        'txn_type',         // PayPal transaction type
        'payment_status',   // PayPal payment status
        'ccbill_ipn',       // CCBill IPN 
        'ct_checkjs',       // skip ct_checkjs field
        'api_mode',         // DigiStore-API
        'loadLastCommentId' // Plugin: WP Discuz. ticket_id=5571
    );
    
    // Fields to replace with ****
    $obfuscate_params = array(
        'password',
        'password_confirmation',
        'pass',
        'pwd',
        'pswd'
    );
    
    // Skip feilds with these strings and known service fields
    $skip_fields_with_strings = array( 
        // Common
        'ct_checkjs', //Do not send ct_checkjs
        'nonce', //nonce for strings such as 'rsvp_nonce_name'
        'security',
        // 'action',
        'http_referer',
        'timestamp',
        'captcha',
        // Formidable Form
        'form_key',
        'submit_entry',
        // Custom Contact Forms
        'form_id',
        'ccf_form',
        'form_page',
        // Qu Forms
        'iphorm_uid',
        'form_url',
        'post_id',
        'iphorm_ajax',
        'iphorm_id',
        // Fast SecureContact Froms
        'fs_postonce_1',
        'fscf_submitted',
        'mailto_id',
        'si_contact_action',
        // Ninja Forms
        'formData_id',
        'formData_settings',
        'formData_fields_\d+_id',
        'formData_fields_\d+_files.*',      
        // E_signature
        'recipient_signature',
        'output_\d+_\w{0,2}',
        // Contact Form by Web-Settler protection
        '_formId',
        '_returnLink',
        // Social login and more
        '_save',
        '_facebook',
        '_social',
        'user_login-',
        'submit',
        'form_token',
        'creation_time',
        'uenc',
        'product',
        'qty',

    );
            
    foreach($skip_params as $value){
        if(array_key_exists($value,$_POST))
        {
            $contact = false;
        }
    } unset($value);
        
    if(count($arr)){
        foreach($arr as $key => $value){
            
            if(gettype($value)=='string'){
                $decoded_json_value = json_decode($value, true);
                if($decoded_json_value !== null)
                {
                    $value = $decoded_json_value;
                }
            }
            
            if(!is_array($value) && !is_object($value)){
                
                if (in_array($key, $skip_params, true) && $key != 0 && $key != '' || preg_match("/^ct_checkjs/", $key))
                {
                    $contact = false;
                }
                
                if($value === '')
                {
                    continue;
                }
                
                // Skipping fields names with strings from (array)skip_fields_with_strings
                foreach($skip_fields_with_strings as $needle){
                    if (preg_match("/".$needle."/", $prev_name.$key) == 1){
                        continue(2);
                    }
                }unset($needle);
                // Obfuscating params
                foreach($obfuscate_params as $needle){
                    if (strpos($key, $needle) !== false){
                        $value = obfuscate_param($value);
                    }
                }unset($needle);
                

                // Removes whitespaces
                $value = urldecode( trim( $value ) ); // Fully cleaned message
                $value_for_email = trim( $value );

                // Email
                if ( ! $email && preg_match( "/^\S+@\S+\.\S+$/", $value_for_email ) ) {
                    $email = $value_for_email;

                // Names
                }elseif (preg_match("/name/i", $key)){
                    
                    preg_match("/(first.?name)?(name.?first)?(forename)?/", $key, $match_forename);
                    preg_match("/(last.?name)?(family.?name)?(second.?name)?(surname)?/", $key, $match_surname);
                    preg_match("/(nick.?name)?(user.?name)?(nick)?/", $key, $match_nickname);
                    
                    if(count($match_forename) > 1)
                    {
                        $nickname['first'] = $value;
                    }
                    elseif(count($match_surname) > 1)
                    {
                        $nickname['last'] = $value;
                    }
                    elseif(count($match_nickname) > 1)
                    {
                        $nickname['nick'] = $value;
                    }
                    else
                    {
                        $message[$prev_name.$key] = $value;
                    }
                
                // Subject
                }elseif ($subject === null && preg_match("/subject/i", $key)){
                    $subject = $value;
                
                // Message
                }else{
                    $message[$prev_name.$key] = $value;                 
                }
                
            }elseif(!is_object($value)){
                
                $prev_name_original = $prev_name;
                $prev_name = ($prev_name === '' ? $key.'_' : $prev_name.$key.'_');
                
                $temp = cleantalkGetFields($value, $message, $email, $nickname, $subject, $contact, $prev_name);
                
                $message    = $temp['message'];
                $email      = ($temp['email']       ? $temp['email'] : null);
                $nickname   = ($temp['nickname']    ? $temp['nickname'] : null);                
                $subject    = ($temp['subject']     ? $temp['subject'] : null);
                if($contact === true)
                {
                    $contact = ($temp['contact'] === false ? false : true);
                }
                $prev_name  = $prev_name_original;
            }
        } unset($key, $value);
    }
            
    //If top iteration, returns compiled name field. Example: "Nickname Firtsname Lastname".
    if($prev_name === ''){
        if(!empty($nickname)){
            $nickname_str = '';
            foreach($nickname as $value){
                $nickname_str .= ($value ? $value." " : "");
            }unset($value);
        }
        $nickname = $nickname_str;
    }
    
    $return_param = array(
        'email'     => $email,
        'nickname'  => $nickname,
        'subject'   => $subject,
        'contact'   => $contact,
        'message'   => $message
    );  
    return $return_param;
}
/**
* Masks a value with asterisks (*)
* @return string
*/
function obfuscate_param($value = null) {
    if ($value && (!is_object($value) || !is_array($value))) {
        $length = strlen($value);
        $value = str_repeat('*', $length);
    }
    return $value;
}
/**
 * Cookie test 
 * @return 
 */
function cleantalk_cookies_set() {
    // Cookie names to validate
    $cookie_test_value = array(
        'cookies_names' => array(),
        'check_value' => cleantalk_get_api_key(),
    );

    // Pervious referer
    if(!empty($_SERVER['HTTP_REFERER'])){
        setcookie('ct_prev_referer', $_SERVER['HTTP_REFERER'], 0, '/');
        $cookie_test_value['cookies_names'][] = 'ct_prev_referer';
        $cookie_test_value['check_value'] .= $_SERVER['HTTP_REFERER'];
    }
    // Cookies test
    $cookie_test_value['check_value'] = md5($cookie_test_value['check_value']);
    setcookie('ct_cookies_test', json_encode($cookie_test_value), 0, '/');
}
/**
 * Cookies test for sender 
 * Also checks for valid timestamp in $_COOKIE['ct_timestamp'] and other ct_ COOKIES
 * @return null|0|1;
 */
function cleantalk_cookies_test()
{   
    if(isset($_COOKIE['ct_cookies_test'])){
        
        $cookie_test = json_decode(stripslashes($_COOKIE['ct_cookies_test']), true);
        
        $check_srting = cleantalk_get_api_key();
        foreach($cookie_test['cookies_names'] as $cookie_name){
            $check_srting .= isset($_COOKIE[$cookie_name]) ? $_COOKIE[$cookie_name] : '';
        } unset($cokie_name);
        
        if($cookie_test['check_value'] == md5($check_srting)){
            return 1;
        }else{
            return 0;
        }
    }else{
        return null;
    }
}
/**
 * CleanTalk integrate register hook
 * @param array $regOptions
 * @param array $theme_vars
 * @return void
 */
function cleantalk_check_register(&$regOptions, $theme_vars){
    
    global $language, $user_info, $modSettings;
    static $executed_check_register = true;

    if (SMF == 'SSI')
        return;

    if (
        $regOptions['interface'] == 'admin' || // Skip admin
        ! $modSettings['cleantalk_check_registrations'] // Skip if registrations check are disabled
    )
        return;

    if ($executed_check_register)
    {
        $executed_check_register = false;

        $ct = new Cleantalk();
        $ct->server_url = CT_SERVER_URL;

        $ct_request = new CleantalkRequest();
        $ct_request->auth_key = cleantalk_get_api_key();

        $ct_request->response_lang = 'en'; // SMF use any charset and language

        $ct_request->agent = CT_AGENT_VERSION;
        $ct_request->sender_email = isset($regOptions['email']) ? $regOptions['email'] : '';

        $ct_request->sender_ip = CleantalkHelper::ip__get(array('real'), false);
        $ct_request->x_forwarded_for = CleantalkHelper::ip__get(array('x_forwarded_for'), false);
        $ct_request->x_real_ip       = CleantalkHelper::ip__get(array('x_real_ip'), false);

        $ct_request->sender_nickname = isset($regOptions['username']) ? $regOptions['username'] : '';

        $ct_request->submit_time = cleantalk_get_form_submit_time();

        $ct_request->js_on = cleantalk_is_valid_js() ? 1 : 0;

        $ct_request->sender_info = json_encode(
            array(
                'REFFERRER'              => isset($_SERVER['HTTP_REFERER'])      ? $_SERVER['HTTP_REFERER']     : null,
                'cms_lang'               => substr($language, 0, 2),                                            
                'USER_AGENT'             => isset($_SERVER['HTTP_USER_AGENT'])   ? $_SERVER['HTTP_USER_AGENT']  : null,
                'ct_options'             => cleantalk_get_ct_options($modSettings),
                'js_timezone'            => !empty($_COOKIE['ct_timezone'])      ? $_COOKIE['ct_timezone']      : null,
                'mouse_cursor_positions' => !empty($_COOKIE['ct_pointer_data'])  ? $_COOKIE['ct_pointer_data']  : null,
                'key_press_timestamp'    => !empty($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : null,
                'page_set_timestamp'     => !empty($_COOKIE['ct_ps_timestamp'])  ? $_COOKIE['ct_ps_timestamp']  : null,
                'REFFERRER_PREVIOUS'     => isset($_COOKIE['ct_prev_referer'])? $_COOKIE['ct_prev_referer']: null,
                'cookies_enabled'        => cleantalk_cookies_test(),
                'js_keys'                => cleantalk_get_js_keys($modSettings)
            )
        );
        $ct_request->post_info = json_encode(array('post_url' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '', 'comment_type' => 'register'));

        if (defined('CT_DEBUG') && CT_DEBUG)
            log_error('CleanTalk request: ' . var_export($ct_request, true), 'user');

        /**
         * @var CleantalkResponse $ct_result CleanTalk API call result
         */
        $ct_result = $ct->isAllowUser($ct_request);

        if($ct_result->errno != 0 && !cleantalk_is_valid_js())
        {
            cleantalk_log('deny registration (errno !=0, invalid js test)' . strip_tags($ct_result->comment));
            fatal_error('CleanTalk: ' . strip_tags($ct_result->comment,"<p><a>"), false);
            return;
        }

        if($ct_result->inactive == 1)
        {
            // need admin approval

            cleantalk_log('need approval for "' . $regOptions['username'] . '"');

            $regOptions['register_vars']['is_activated'] = 3; // waiting for admin approval
            $regOptions['require'] = 'approval';

            // temporarly turn on notify for new registration
            if (!isset($modSettings['cleantalk_email_notifications']) || empty($modSettings['cleantalk_email_notifications']))
                $modSettings['cleantalk_email_notifications'] = 1;

            // add Cleantalk message to email template
            $user_info['cleantalkmessage'] = $ct_result->comment;

            // temporarly turn on registration_method to approval_after
            $modSettings['registration_method'] = 2;
            return;
        }

        if ($ct_result->allow == 0){
            // this is bot, stop registration
            cleantalk_log('deny registration' . strip_tags($ct_result->comment));
            cleantalk_after_create_topic('Deny registration. Reason: ' . strip_tags($ct_result->comment).'. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email);
            fatal_error('CleanTalk: ' . strip_tags($ct_result->comment,"<p><a>"), false);
        } else {
            // all ok, only logging
            cleantalk_log('allow regisration for "' . $regOptions['username'] . '"');
            cleantalk_after_create_topic('Allow registration. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email);
        }        
    }

}
function cleantalk_check_personal_messages($recipients, $from, $subject, $message)
{
    global $language, $user_info, $modSettings, $smcFunc;
    
    if (SMF == 'SSI')
        return;

    if(!$user_info['is_admin'] && (isset($modSettings['cleantalk_check_personal_messages']) && $modSettings['cleantalk_check_personal_messages']) && isset($user_info['groups'][1]) && $user_info['groups'][1] === 4)
    {
        if (isset($from))
        {
            $sql = "SELECT email_address FROM {db_prefix}members WHERE member_name='".$from."'";
            $result = $smcFunc['db_query']('', $sql, Array());
            while ($email_address = $smcFunc['db_fetch_assoc']($result))
                $sender_email = $email_address['email_address'];
        }
        $ct = new Cleantalk();
        $ct->server_url = CT_SERVER_URL;

        $ct_request = new CleantalkRequest();
        $ct_request->auth_key = cleantalk_get_api_key();

        $ct_request->response_lang = 'en'; // SMF use any charset and language

        $ct_request->agent = CT_AGENT_VERSION;

        $ct_request->sender_email = isset($sender_email) ? $sender_email : '';

        $ct_request->sender_ip = CleantalkHelper::ip__get(array('real'), false);
        $ct_request->x_forwarded_for = CleantalkHelper::ip__get(array('x_forwarded_for'), false);
        $ct_request->x_real_ip       = CleantalkHelper::ip__get(array('x_real_ip'), false);

        $ct_request->sender_nickname = isset($from) ? $from : '';
        $ct_request->message = isset($subject) ? $subject."\n".$message : $message;

        $ct_request->submit_time = cleantalk_get_form_submit_time();

        $ct_request->js_on = cleantalk_is_valid_js() ? 1 : 0;

        $ct_request->sender_info = json_encode(
            array(
                'REFFERRER'              => isset($_SERVER['HTTP_REFERER'])      ? $_SERVER['HTTP_REFERER']     : null,
                'cms_lang'               => substr($language, 0, 2),                                            
                'USER_AGENT'             => isset($_SERVER['HTTP_USER_AGENT'])   ? $_SERVER['HTTP_USER_AGENT']  : null,
                'ct_options'             => cleantalk_get_ct_options($modSettings),
                'js_timezone'            => isset($_COOKIE['ct_timezone'])       ? $_COOKIE['ct_timezone']      : null,
                'mouse_cursor_positions' => isset($_COOKIE['ct_pointer_data'])   ? $_COOKIE['ct_pointer_data']  : null,
                'key_press_timestamp'    => !empty($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : null,
                'page_set_timestamp'     => !empty($_COOKIE['ct_ps_timestamp'])  ? $_COOKIE['ct_ps_timestamp']  : null,
                'REFFERRER_PREVIOUS'     => isset($_COOKIE['ct_prev_referer'])? $_COOKIE['ct_prev_referer']: null,
                'cookies_enabled'        => cleantalk_cookies_test(),
                'js_keys'                => cleantalk_get_js_keys($modSettings)
            )
        );
        $ct_request->post_info = json_encode(array('post_url' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '', 'comment_type' => 'personal_message'));      
        $ct_result = $ct->isAllowMessage($ct_request); 

        if($ct_result->errno != 0 && !cleantalk_is_valid_js())
        {
            cleantalk_log('deny registration (errno !=0, invalid js test)' . strip_tags($ct_result->comment));
            fatal_error('CleanTalk: ' . strip_tags($ct_result->comment,"<p><a>"), false);
            return;
        } 

        if ($ct_result->allow == 0){
            // this is bot, stop registration
            cleantalk_log('deny personal message' . strip_tags($ct_result->comment));
            cleantalk_after_create_topic('Deny personal message. Reason: ' . strip_tags($ct_result->comment).'. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email);
            fatal_error('CleanTalk: ' . strip_tags($ct_result->comment,"<p><a>"), false);
        } else {
            // all ok, only logging
            cleantalk_log('allow personal message for "' . $from . '"');
            cleantalk_after_create_topic('Allow personal message. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email);
        }               
    }
}
/**
 * Cleantalk check posts function
 * @param array $msgOptions
 * @param array $topicOptions
 * @param array $posterOptions
 */
function cleantalk_check_message(&$msgOptions, $topicOptions, $posterOptions){
    
    global $language, $user_info, $modSettings, $smcFunc, $db_connection;
    static $executed_check_message = true;

    if (SMF == 'SSI') {
        return;
    }
    if ($executed_check_message)
    {
        $executed_check_message = false;

        // Do not check admin
        if(!$user_info['is_admin'] && ($user_info['is_guest'] == 1 || ($modSettings['cleantalk_first_post_checking'] && isset($user_info['groups'][1]) && $user_info['groups'][1] === 4)))
        {
            $ct = new Cleantalk();
            $ct->server_url = CT_SERVER_URL;

            $ct_request = new CleantalkRequest();
            $ct_request->auth_key = cleantalk_get_api_key();

            $ct_request->response_lang = 'en'; // SMF use any charset and language

            $ct_request->agent = CT_AGENT_VERSION;

            $ct_request->sender_email = isset($posterOptions['email']) ? $posterOptions['email'] : '';

            $ct_request->sender_ip = CleantalkHelper::ip__get(array('real'), false);
            $ct_request->x_forwarded_for = CleantalkHelper::ip__get(array('x_forwarded_for'), false);
            $ct_request->x_real_ip       = CleantalkHelper::ip__get(array('x_real_ip'), false);

            $ct_request->sender_nickname = isset($posterOptions['name']) ? $posterOptions['name'] : '';
            $ct_request->message = isset($msgOptions['subject']) ? preg_replace('/\s+/', ' ',str_replace("<br />", " ", $msgOptions['subject']))."\n".preg_replace('/\s+/', ' ',str_replace("<br />", " ", $msgOptions['body'])) : preg_replace('/\s+/', ' ',str_replace("<br />", " ", $msgOptions['body']));

            $ct_request->submit_time = cleantalk_get_form_submit_time();

            $ct_request->js_on = cleantalk_is_valid_js() ? 1 : 0;

            $ct_request->sender_info = json_encode(
                array(
                    'REFFERRER'              => isset($_SERVER['HTTP_REFERER'])      ? $_SERVER['HTTP_REFERER']     : null,
                    'cms_lang'               => substr($language, 0, 2),                                            
                    'USER_AGENT'             => isset($_SERVER['HTTP_USER_AGENT'])   ? $_SERVER['HTTP_USER_AGENT']  : null,
                    'ct_options'             => cleantalk_get_ct_options($modSettings),
                    'js_timezone'            => isset($_COOKIE['ct_timezone'])       ? $_COOKIE['ct_timezone']      : null,
                    'mouse_cursor_positions' => isset($_COOKIE['ct_pointer_data'])   ? $_COOKIE['ct_pointer_data']  : null,
                    'key_press_timestamp'    => !empty($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : null,
                    'page_set_timestamp'     => !empty($_COOKIE['ct_ps_timestamp'])  ? $_COOKIE['ct_ps_timestamp']  : null,
                    'REFFERRER_PREVIOUS'     => isset($_COOKIE['ct_prev_referer'])? $_COOKIE['ct_prev_referer']: null,
                    'cookies_enabled'        => cleantalk_cookies_test(),
                    'js_keys'                => cleantalk_get_js_keys($modSettings)
                )
            );
            $ct_request->post_info = json_encode(array('post_url' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '', 'comment_type' => 'comment'));
            if (isset($topicOptions['id'])) {
                
                if(!isset($db_connection) || $db_connection === false)
                        loadDatabase();
                    
                if(isset($db_connection) && $db_connection != false){
                    
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
            }

            if(defined('CT_DEBUG') && CT_DEBUG)
                log_error('CleanTalk request: ' . var_export($ct_request, true), 'user');

            /**
             * @var CleantalkResponse $ct_result CleanTalk API call result
             */
            $ct_result = $ct->isAllowMessage($ct_request);
            $ct_answer_text = 'CleanTalk: ' . strip_tags($ct_result->comment, "<p><a>");

            if($ct_result->errno != 0 && !cleantalk_is_valid_js()){
                cleantalk_log('deny post (errno !=0, invalid js test)' . strip_tags($ct_result->comment));
                fatal_error($ct_answer_text, false);

                return;
            }
            if ($ct_result->allow == 0){
                $msgOptions['cleantalk_check_message_result'] = $ct_result->comment;
                if ($modSettings['cleantalk_automod']){
                    if ($ct_result->stop_queue == 1){
                        cleantalk_log('spam message "' . $ct_result->comment . '"');
                        cleantalk_after_create_topic('Spam message blocked. Reason: ' . strip_tags($ct_result->comment).'. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email.'<br/>Message: '.$ct_request->message);
                        fatal_error($ct_answer_text, false);
                    }else{
                        // If post moderation active then set message not approved
                        cleantalk_log('to postmoderation "' . $ct_result->comment . '"');
                        cleantalk_after_create_topic('Suspicious spam message send to postmoderation. Reason: ' . strip_tags($ct_result->comment).'. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email.'<br/>Message: '.$ct_request->message);
                        $msgOptions['approved'] = 0;
                    }
                }else{
                    cleantalk_log('spam message "' . $ct_result->comment . '"');
                    cleantalk_after_create_topic('Spam message blocked. Reason: ' . strip_tags($ct_result->comment).'. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email.'<br/>Message: '.$ct_request->message);
                    fatal_error($ct_answer_text, false);
                }
            }else{
                // all ok, only logging
                cleantalk_log('allow message for "' . $posterOptions['name'] . '"');
                cleantalk_after_create_topic('Allow message. <br/>Username: '. $ct_request->sender_nickname.'<br/>E-mail'.$ct_request->sender_email.'<br/>Message: '.$ct_request->message);
            }
        }
    }
    
}

/**
 * Get CleanTalk hidden js code
 * @return string
 */
function cleantalk_get_checkjs_code(){
    
    global $modSettings;
    
    $api_key = isset($modSettings['cleantalk_api_key']) ? $modSettings['cleantalk_api_key'] : null;
    $js_keys = isset($modSettings['cleantalk_js_keys']) ? json_decode($modSettings['cleantalk_js_keys'], true) : null;

    $key = rand();
    $latest_key_time = 0;

    if ($js_keys && isset($js_keys['keys'])) {

        $keys = $js_keys['keys'];
        $keys_checksum = md5(json_encode($keys));

        if ($keys && is_array($keys) && !empty($keys))
        {
            foreach ($keys as $k => $t) {

                // Removing key if it's to old
                if (time() - (int)$t > $js_keys['js_keys_amount'] * 86400) {
                    unset($keys[$k]);
                    continue;
                }

                if ($t > $latest_key_time) {
                    $latest_key_time = $t;
                    $key = $k;
                }
            }
            // Get new key if the latest key is too old
            if (time() - (int)$latest_key_time > $js_keys['js_key_lifetime']) {
                $keys[$key] = time();
            }           
        }
        else $keys = array($key => time());
                    
        if (md5(json_encode($keys)) != $keys_checksum) {
            $js_keys = array(
                'keys' => $keys, // Keys to do JavaScript antispam test 
                'js_keys_amount' => 24, // JavaScript keys store days - 8 days now
                'js_key_lifetime' => 86400, // JavaScript key life time in seconds - 1 day now
            );
            updateSettings(array('cleantalk_js_keys' => json_encode($js_keys)), false); 
        }        
    }
                           
    return $key;
}

/**
 * Get CleanTalk API KEY from SMF settings
 * @return string
 */
function cleantalk_get_api_key(){
    
    global $modSettings;

    return isset($modSettings['cleantalk_api_key']) ? $modSettings['cleantalk_api_key'] : null;
}

/**
 * Return CleanTalk javascript verify code
 */
function cleantalk_print_js_input()
{
    
    $value = cleantalk_get_checkjs_code();
    
    return '<script type="text/javascript">
        var ct_date = new Date(), 
            ctTimeMs = new Date().getTime(),
            ctMouseEventTimerFlag = true, //Reading interval flag
            ctMouseData = [],
            ctMouseDataCounter = 0;

        function ctSetCookie(c_name, value) {
            document.cookie = c_name + "=" + encodeURIComponent(value) + "; path=/";
        }
        ctSetCookie("ct_ps_timestamp", Math.floor(new Date().getTime()/1000));
        ctSetCookie("ct_fkp_timestamp", "0");
        ctSetCookie("ct_pointer_data", "0");
        ctSetCookie("ct_timezone", "0");

        setTimeout(function(){
            ctSetCookie("ct_checkjs", "'.$value.'");
            ctSetCookie("ct_timezone", ct_date.getTimezoneOffset()/60*(-1));
        },1000);

        //Writing first key press timestamp
        var ctFunctionFirstKey = function output(event){
            var KeyTimestamp = Math.floor(new Date().getTime()/1000);
            ctSetCookie("ct_fkp_timestamp", KeyTimestamp);
            ctKeyStopStopListening();
        }

        //Reading interval
        var ctMouseReadInterval = setInterval(function(){
            ctMouseEventTimerFlag = true;
        }, 150);
            
        //Writting interval
        var ctMouseWriteDataInterval = setInterval(function(){
            ctSetCookie("ct_pointer_data", JSON.stringify(ctMouseData));
        }, 1200);

        //Logging mouse position each 150 ms
        var ctFunctionMouseMove = function output(event){
            if(ctMouseEventTimerFlag == true){
                
                ctMouseData.push([
                    Math.round(event.pageY),
                    Math.round(event.pageX),
                    Math.round(new Date().getTime() - ctTimeMs)
                ]);
                
                ctMouseDataCounter++;
                ctMouseEventTimerFlag = false;
                if(ctMouseDataCounter >= 100){
                    ctMouseStopData();
                }
            }
        }

        //Stop mouse observing function
        function ctMouseStopData(){
            if(typeof window.addEventListener == "function"){
                window.removeEventListener("mousemove", ctFunctionMouseMove);
            }else{
                window.detachEvent("onmousemove", ctFunctionMouseMove);
            }
            clearInterval(ctMouseReadInterval);
            clearInterval(ctMouseWriteDataInterval);                
        }

        //Stop key listening function
        function ctKeyStopStopListening(){
            if(typeof window.addEventListener == "function"){
                window.removeEventListener("mousedown", ctFunctionFirstKey);
                window.removeEventListener("keydown", ctFunctionFirstKey);
            }else{
                window.detachEvent("mousedown", ctFunctionFirstKey);
                window.detachEvent("keydown", ctFunctionFirstKey);
            }
        }

        if(typeof window.addEventListener == "function"){
            window.addEventListener("mousemove", ctFunctionMouseMove);
            window.addEventListener("mousedown", ctFunctionFirstKey);
            window.addEventListener("keydown", ctFunctionFirstKey);
        }else{
            window.attachEvent("onmousemove", ctFunctionMouseMove);
            window.attachEvent("mousedown", ctFunctionFirstKey);
            window.attachEvent("keydown", ctFunctionFirstKey);
        }
    </script>';
}
/**
 * Calling by hook integrate_exit
 */
function cleantalk_exit()
{
    global $context, $user_info;
    if (
        isset($context['template_layers']) &&
        is_array($context['template_layers']) &&
        in_array('body', $context['template_layers']) &&
        ($user_info['is_guest'] || $user_info['posts'] == 0)
    ) {
        cleantalk_store_form_start_time();
    }
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
    if (cleantalk_cookies_test() == 1)
    {
        if (isset($_SESSION['ct_form_start_time']))
            return time() - intval($_SESSION['ct_form_start_time']);
        elseif (isset($_COOKIE['ct_ps_timestamp']))
            return time() - intval($_COOKIE['ct_ps_timestamp']);        
    }
    return null;
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
 * Logging message into SMF log
 * @param string $message
 */
function cleantalk_after_create_topic( $message ){
    
    global $sourcedir, $modSettings;
    
    if(
        array_key_exists( 'cleantalk_email_notifications', $modSettings ) &&
        $modSettings['cleantalk_email_notifications'] &&
        $message
    ){
        require_once($sourcedir . '/Subs-Admin.php');
        
        if( is_array( $message ) )
            $message = CleantalkHelper::array_implode__recursive( "\n", $message );
        
        emailAdmins(
            'send_email',
            array(
                'EMAILSUBJECT' => '[Cleantalk antispam for the board]',
                'EMAILBODY'    => "CleanTalk antispam checking result: \n$message",
            )
        );
    }
}
/**
 * Calling by hook integrate_load_theme
 */
function cleantalk_load()
{
    global $context, $user_info, $modSettings, $smcFunc, $db_connection;
        
    if(SMF == 'SSI'){
        return;
    }
    
    if (
        isset($context['template_layers']) &&
        is_array($context['template_layers']) &&
        in_array('body', $context['template_layers']) &&
        ($user_info['is_guest'] || $user_info['posts'] == 0) &&
        !$user_info['is_admin']//!cleantalk_is_valid_js()
    ) {
        
        // Output JS for users
        $context ['html_headers'] .= cleantalk_print_js_input();
    }
    
    // Only for admin
    if(!empty($user_info['is_admin'])){
               
        // Deleting selected users
        if(Post::get('ct_del_user'))
        {
            checkSession('request');
            
            if (!isset($db_connection) || $db_connection === false)
                loadDatabase();
            
            if (isset($db_connection) && $db_connection != false)
            {
                foreach(Post::get('ct_del_user') as $key=>$value)
                {
                    $result = $smcFunc['db_query']('', 'delete from {db_prefix}members where id_member='.intval($key),Array('db_error_skip' => true));
                    $result = $smcFunc['db_query']('', 'delete from {db_prefix}topics where id_member_started='.intval($key),Array('db_error_skip' => true));
                    $result = $smcFunc['db_query']('', 'delete from {db_prefix}messages where id_member='.intval($key),Array('db_error_skip' => true));
                }
            }
        }
        
        // Deleting all users
        if(Post::get('ct_delete_all'))
        {
            checkSession('request');
            
            if (!isset($db_connection) || $db_connection === false)
                loadDatabase();
            
            if (isset($db_connection) && $db_connection != false)
            {
                $result = $smcFunc['db_query']('', 'select * from {db_prefix}members where ct_marked=1',Array());
                while($row = $smcFunc['db_fetch_assoc'] ($result))
                {
                    $tmp = $smcFunc['db_query']('', 'delete from {db_prefix}topics where id_member_started='.$row['id_member'],Array('db_error_skip' => true));
                    $tmp = $smcFunc['db_query']('', 'delete from {db_prefix}messages where id_member='.$row['id_member'],Array('db_error_skip' => true));
                }
                $result = $smcFunc['db_query']('', 'delete from {db_prefix}members where ct_marked=1',Array('db_error_skip' => true));
            }
        }
    }
    
    /* Cron for account status */
    if(isset($modSettings['cleantalk_api_key_is_ok']) && $modSettings['cleantalk_api_key_is_ok'] == '1' && isset($modSettings['cleantalk_last_account_check']) && $modSettings['cleantalk_last_account_check'] < time() - 86400){
        
        $result = CleantalkAPI::method__notice_paid_till($modSettings['cleantalk_api_key'], preg_replace('/http[s]?:\/\//', '', $_SERVER['HTTP_HOST'], 1));
        
        if(empty($result['error'])){
            $settings_array = array(
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
                'cleantalk_errors' => '', 
            );
            updateSettings($settings_array, false);
        }        
    }
    
    // Add "tell others" templates
    if (isset($context['template_layers'])
        && $context['template_layers'] === array('html', 'body')
        && array_key_exists('cleantalk_tell_others', $modSettings)
        && $modSettings['cleantalk_tell_others']
    ){
        $context['template_layers'][] = 'cleantalk';
    }
}


/**
 * Is Javascript enabled and valid
 * @return bool
 */
function cleantalk_is_valid_js()
{
    if(isset($_COOKIE['ct_checkjs']) && $_COOKIE['ct_checkjs']){
                
        global $modSettings;
        
        $js_keys = isset($modSettings['cleantalk_js_keys']) ? json_decode($modSettings['cleantalk_js_keys'], true) : null;
        $keys = isset($js_keys['keys']) ? $js_keys['keys'] : false;
        if($keys && is_array($keys)){
            $result = isset($keys[$_COOKIE['ct_checkjs']]) ? 1 : 0;
        }else{
            $result = false;
        }
        
    }else
        $result = false;
    
    return  $result;
}
/**
 * Above content. Banners
 */
function template_cleantalk_above()
{
    global $user_info, $modSettings, $txt, $boardurl;
    
    if($user_info['is_admin'] && isset($_GET['action']) && $_GET['action'] == 'admin'){
        
        $source_dir = $boardurl . '/Sources/cleantalk/';
        
        echo "<div class='notice_wrapper'>";
        
            // Renew banner
            if(!empty($modSettings['cleantalk_show_notice']) && !empty($modSettings['cleantalk_renew'])){
                echo "<div style='margin-bottom: 1.2em; padding: 5px;'>"
                    ."<h1>"
                        ."<img style='height: 20px; margin: 0 5px 0 0; position: relative; top: 5px;' src='{$source_dir}attention.png' />"
                        .sprintf($txt['cleantalk_banner_renew_1'], "<a href='http://cleantalk.org/my/bill/recharge?cp_mode=antispam'><u>{$txt['cleantalk_banner_renew_2']}</u></a>")
                    ."</h1>"
                ."</div>";
            }
            
            // Trial banner
            if(!empty($modSettings['cleantalk_show_notice']) && !empty($modSettings['cleantalk_trial'])){
                echo "<div style='margin-bottom: 1.2em; padding: 5px;'>"
                    ."<h1>"
                        ."<img style='height: 20px; margin: 0 5px 0 0; position: relative; top: 5px;' src='{$source_dir}attention.png' />"
                        .sprintf($txt['cleantalk_banner_trial_1'], "<a href='http://cleantalk.org/my/bill/recharge?cp_mode=antispam' target=\"_blank\"><u>{$txt['cleantalk_banner_trial_2']}</u></a>")
                    ."</h1>"
                ."</div>";
            }
            
            // Review banner // INACTIVE
            // if(!empty($modSettings['cleantalk_show_notice']) && !empty($modSettings['cleantalk_show_review'])){
                // echo "<div style='margin-bottom: 1.2em; padding: 5px;'>"
                    // ."<h1>"
                        // ."<img style='height: 20px; margin: 0 5px 0 0; position: relative; top: 5px;' src='{$source_dir}attention.png' />"
                        // .sprintf($txt['cleantalk_banner_bad_key_1'], "<a href='{$_SERVER['HTTP_HOST']}/index.php?action=admin;area=modsettings;'><u>{$txt['cleantalk_banner_bad_key_2']}</u></a>")
                    // ."</h1>"
                // ."</div>";
            // }
            
            // Bad key banner
            if(empty($modSettings['cleantalk_api_key_is_ok']) && (empty($_GET['area'])  || (isset($_GET['area']) && $_GET['area'] != 'modsettings'))){
                
                echo "<div style='margin-bottom: 1.2em; padding: 5px;'>"
                    ."<h1>"
                        ."<img style='height: 20px; margin: 0 5px 0 0; position: relative; top: 5px;' src='{$source_dir}attention.png' />"
                        .sprintf($txt['cleantalk_banner_bad_key_1'], "<a href='index.php?action=admin;area=modsettings;'><u>{$txt['cleantalk_banner_bad_key_2']}</u></a>")
                    ."</h1>"
                ."</div>";
            }   
            
        echo "</div>";
    }
}

/**
 * Below content
 */
function template_cleantalk_below()
{
    global $modSettings, $txt;

    if (SMF == 'SSI') {
        return;
    }

    if(!empty($modSettings['cleantalk_tell_others'])){
        $message = $txt['cleantalk_tell_others_footer_message'];
        echo '<div class="cleantalk_tell_others" style="text-align: center;padding:5px 0;">', $message, '</div>';
    }
}

function cleantalk_buffer($buffer)
{
    
    global $modSettings, $user_info, $smcFunc, $txt, $forum_version, $db_connection;
    
    if (SMF == 'SSI')
        return $buffer;

    if(isset($_GET['action'], $_GET['area']) && $_GET['action'] == 'admin' && $_GET['area'] == 'modsettings'){
        
        if(strpos($forum_version, 'SMF 2.0')===false){
            
            $html='';
            
        }else{
            
            $html='<span id="ct_anchor"></span><script>
            document.getElementById("ct_anchor").parentElement.style.height="0px";
            document.getElementById("ct_anchor").parentElement.style.padding="0px";
            document.getElementById("ct_anchor").parentElement.style.border="0px";
            </script>';
            
        }

        if (!isset($db_connection) || $db_connection === false)
            loadDatabase();
        
        if (isset($db_connection) && $db_connection != false){
            
            if(isset($_GET['ctcheckspam'])){
                
                if(isset($modSettings['cleantalk_api_key_is_ok']) && $modSettings['cleantalk_api_key_is_ok'] == '1' && $modSettings['cleantalk_api_key'] != ''){
                    
                    db_extend('packages');
                    
                    // Unmark all users
                    $sql = 'UPDATE {db_prefix}members SET ct_marked = {int:default_value}';
                    $result = $smcFunc['db_query']('', $sql, array('default_value' => 0));
                    
                    // Cicle params
                    $offset = 0;
                    $per_request = 500;
                    
                    // Getting users to check
                    // Making at least one DB query
                    do{
                        
                        $sql = "SELECT id_member, member_name, date_registered, last_login, email_address, member_ip FROM {db_prefix}members where passwd <> '' LIMIT $offset,$per_request";
                        $result = $smcFunc['db_query']('', $sql, Array());
                                                
                        // Break if result is empty.
                        if($smcFunc['db_num_rows'] ($result) == 0)
                            break;
                        
                        // Setting data
                        $data = array();
                        while($row = $smcFunc['db_fetch_assoc'] ($result)){
                            $data[] = $row['email_address'];
                            $data[] = $row['member_ip'];
                        }
                        
                        // Request
                        $api_result = CleantalkAPI::method__spam_check_cms(cleantalk_get_api_key(), $data);
                        
                        // Error handling
                        if(!empty($api_result['error'])){
                            break;
                        }else{
                                
                            foreach($api_result as $key => $value){
                                
                                // Mark spam users
                                if($key === filter_var($key, FILTER_VALIDATE_IP)){
                                    if($value['appears'] == 1){
                                        $sql = 'UPDATE {db_prefix}members set ct_marked=1 where member_ip="'.$key.'"';
                                        $sub_result = $smcFunc['db_query']('', $sql, Array('db_error_skip' => true));
                                    }
                                }else{
                                    if($value['appears'] == 1){
                                        $sql = 'UPDATE {db_prefix}members set ct_marked=1 where email_address="'.$key.'"';
                                        $sub_result = $smcFunc['db_query']('', $sql, Array('db_error_skip' => true));
                                    }
                                }
                            }
                            unset($key, $value);
                        }
                        
                        $offset += $per_request;
                        
                    } while( true );
                    
                    // Free result when it's all done
                    $smcFunc['db_free_result']($result);
                    
                    // Error output
                    if(!empty($api_result['error']) && isset($api_result['error_string'])){
                        $html.='<center>'
                                .'<div style="border:2px solid red;color:red;font-size:16px;width:300px;padding:5px;">'
                                    .'<b>'.$api_result['error_string'].'</b>'
                                .'</div>'
                                .'<br>'
                            .'</center>';
                    }
                    
                    $sql = "SELECT * FROM {db_prefix}members WHERE ct_marked=1";
                    $result = $smcFunc['db_query']('', $sql, Array());
                    
                    if($smcFunc['db_num_rows'] ($result) == 0 && isset($_GET['ctcheckspam'])){
                        
                        $html.='<center><div><b>'.$txt['cleantalk_check_users_nofound'].'</b></div><br><br></center>';
                        
                    }else if($smcFunc['db_num_rows'] ($result) > 0){
                        
                        if(isset($_GET['ctcheckspam'])){
                            $html.='<center><h3>'.$txt['cleantalk_check_users_done'].'</h3><br /><br /></center>';
                        }
                        
                        // Pagination           
                        $on_page = 20;
                        $pages = ceil(intval($smcFunc['db_num_rows'] ($result))/$on_page);
                        $page = !empty($_GET['spam_page']) ? intval($_GET['spam_page']) : 1;
                        $offset = ($page-1)*$on_page;
                        
                        $sql = "SELECT * FROM {db_prefix}members WHERE ct_marked=1 LIMIT $offset, $on_page";
                        $result = $smcFunc['db_query']('', $sql, Array());
                        
                        if($pages > 1){
                            $html.= "<div style='margin: 10px;'>"
                                    ."<b>".$txt['cleantalk_check_users_pages'].":</b>"
                                    ."<ul style='display: inline-block; margin: 0; padding: 0;'>";
                                        for($i = 1; $i <= $pages; $i++){
                                            $html.= "<li style='display: inline-block;  margin-left: 10px;'>"
                                                    ."<a href='".preg_replace('/(&spam_page=.*)/', '', $_SERVER['REQUEST_URI'])."&spam_page=$i&ctcheckspam=1'>"
                                                        .($i == $page ? "<span style='font-size: 1.1em; font-weight: 600;'>$i</span>" : $i)
                                                    ."</a>"
                                                ."</li>";
                                        }
                                $html.= "</ul>";
                            $html.= "</div>";
                        }
                        
                        $html.='<center><table style="border-color:#666666;" border=1 cellspacing=0 cellpadding=3>'
                            .'<thead>'
                            .'<tr>'
                                .'<th>'.$txt['cleantalk_check_users_tbl_select'].'</th>'
                                .'<th>'.$txt['cleantalk_check_users_tbl_username'].'</th>'
                                .'<th>'.$txt['cleantalk_check_users_tbl_joined'].'</th>'
                                .'<th>E-mail</th>'
                                .'<th>IP</th>'
                                .'<th>'.$txt['cleantalk_check_users_tbl_lastvisit'].'</th>'
                                .'<th>'.$txt['cleantalk_check_users_tbl_posts'].'</th>'
                            .'</tr>'
                            .'</thead>'
                            .'<tbody>';
                            
                        $found=false;
                        
                        while($row = $smcFunc['db_fetch_assoc'] ($result)){

                            $found=true;
                            $html.="<tr>
                            <td><input type='checkbox' name=ct_del_user[".$row['id_member']."] value='1' /></td>
                            <td>{$row['member_name']}&nbsp;<sup><a href='index.php?action=profile;u={$row['id_member']}' target='_blank'>{$txt['cleantalk_check_users_tbl_username_details']}</a></sup></td>
                            <td>".date("Y-m-d H:i:s",$row['date_registered'])."</td>
                            <td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['email_address']."'><img src='https://cleantalk.org/images/icons/external_link.gif' border='0'/> ".$row['email_address']."</a></td>
                            <td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['member_ip']."'><img src='https://cleantalk.org/images/icons/external_link.gif' border='0'/> ".$row['member_ip']."</a></td>
                            <td>".date("Y-m-d H:i:s",$row['last_login'])."</td>
                            <td style='text-align: center;'>{$row['posts']}&nbsp;<sup><a href='index.php?action=profile;area=showposts;u={$row['id_member']}' target='_blank'>{$txt['cleantalk_check_users_tbl_posts_show']}</a></sup></td>
                            </tr>";
                            
                        }
                        
                        $html.="</tbody></table></center>";
                        
                        if($pages > 1){
                            $html.= "<div style='margin: 10px;'>"
                                    ."<b>".$txt['cleantalk_check_users_pages'].":</b>"
                                    ."<ul style='display: inline-block; margin: 0; padding: 0;'>";
                                        for($i = 1; $i <= $pages; $i++){
                                            $html.= "<li style='display: inline-block;  margin-left: 10px;'>"
                                                    ."<a href='".preg_replace('/(&spam_page=.*)/', '', $_SERVER['REQUEST_URI'])."&spam_page=$i&ctcheckspam=1'>"
                                                        .($i == $page ? "<span style='font-size: 1.1em; font-weight: 600;'>$i</span>" : $i)
                                                    ."</a>"
                                                ."</li>";
                                        }
                                $html.= "</ul>";
                            $html.= "</div>";
                        }
                        
                        $html.="<br /><center><input type=submit name='ct_delete_checked' value='".$txt['cleantalk_check_users_tbl_delselect']."' onclick='return confirm(\"".$txt['cleantalk_check_users_confirm']."\")'> <input type=submit name='ct_delete_all' value='".$txt['cleantalk_check_users_tbl_delall']."' onclick='return confirm(\"".$txt['cleantalk_check_users_confirm']."\")'><br />".$txt['cleantalk_check_users_tbl_delnotice']."<br /><br /></center>";
                    }
                }else{
                    $html.='<center><div><b>'.$txt['cleantalk_check_users_key_is_bad'].'</b></div><br><br></center>';
                }
            }
        
            $html.="<center><button style=\"width:20%;\" id=\"check_spam\" onclick=\"location.href=location.href.replace('&finishcheck=1','').replace('&ctcheckspam=1','').replace('&ctgetautokey=1','')+'&ctcheckspam=1';return false;\">".$txt['cleantalk_check_users_button']."</button><br /><br />".$txt['cleantalk_check_users_button_after']."</center>";
        }
        $buffer = str_replace("%CLEANTALK_CHECK_USERS%", $html, $buffer);
        
    // Key auto getting, Key buttons, Control panel button 
        
        $cleantalk_api_key = isset( $modSettings['cleantalk_api_key'] ) ? $modSettings['cleantalk_api_key'] : '';
        $cleantalk_key_html = '<input type="text" name="cleantalk_api_key" id="cleantalk_api_key" value="'.$cleantalk_api_key.'" class="input_text">';
        if (isset($modSettings['cleantalk_api_key_is_ok']) && $modSettings['cleantalk_api_key_is_ok'] == '1')
        {
            $cleantalk_key_html .= "&nbsp<span style='color: green;'>".$txt['cleantalk_key_valid']."</span>";
            if (isset($modSettings['cleantalk_account_name_ob']) && $modSettings['cleantalk_account_name_ob'] != '')
                $cleantalk_key_html.= "<br><b>".$txt['cleantalk_account_name_ob']." ".$modSettings['cleantalk_account_name_ob']."</b>";
            elseif (isset($modSettings['cleantalk_moderate_ip']) && $modSettings['cleantalk_moderate_ip'] == '1' && isset($modSettings['cleantalk_ip_license']) && $modSettings['cleantalk_ip_license'] != '')
                $cleantalk_key_html.= "<br><b>".$txt['cleantalk_moderate_ip']." ".$modSettings['cleantalk_ip_license']."</b>";
            $cleantalk_key_html .= '<br><br><a target="_blank" href="https://cleantalk.org/my?user_token='.$modSettings['cleantalk_user_token'].'&cp_mode=antispam" style="display: inline-block;"><input type="button" value="'.$txt['cleantalk_get_statistics'].'"></a><br><br>';            
        }
        else
        {
            $cleantalk_key_html .= "&nbsp<span style='color: red;'>".((isset($modSettings['cleantalk_errors']) && !empty($modSettings['cleantalk_errors'])) ? $modSettings['cleantalk_errors'] : $txt['cleantalk_key_not_valid'])."</span>";
            $cleantalk_key_html .= "<br><br><a target='_blank' href='https://cleantalk.org/register?platform=smf&email=".urlencode($user_info['email'])."&website=".urlencode($_SERVER['SERVER_NAME'])."&product_name=antispam'>
                    <input type='button' value='".$txt['cleantalk_get_access_manually']."' />
                </a> {$txt['cleantalk_get_access_key_or']} ";
            $cleantalk_key_html .= '<input name="spbc_get_apikey_auto" type="submit" class="spbc_manual_link" value="'.$txt['cleantalk_get_access_automatically'].'" onclick="location.href=location.href.replace(\'&finishcheck=1\',\'\').replace(\'&ctcheckspam=1\',\'\').replace(\'&ctgetautokey=1\',\'\')+\'&ctgetautokey=1\';return false;"/>';
            $cleantalk_key_html .= "<br/><br/>";
            $cleantalk_key_html .= "<div style='font-size: 10pt; color: #666 !important'>" . sprintf($txt['cleantalk_admin_email_will_be_used'], $user_info['email']) . "</div>";
            $cleantalk_key_html .= "<div style='font-size: 10pt; color: #666 !important'><a target='__blank' style='color:#BBB;' href='https://cleantalk.org/publicoffer'> ".$txt['cleantalk_license_agreement']." </a></div><br><br>";            
        }
        
        $buffer = preg_replace('/<input type="text" name="cleantalk_api_key" id="cleantalk_api_key" value="'.$cleantalk_api_key.'"\s?(class="input_text")?\s?\/?>/',$cleantalk_key_html, $buffer, 1);
        
    }
    
    return $buffer;
}

/**
 * Get plugin settings (ct_options)
 *
 * @param $mod_settings
 * @return array
 */
function cleantalk_get_ct_options($mod_settings) {
    $ct_options = array();

    foreach ($mod_settings as $key => $value) {
        if(strpos($key, 'cleantalk') !== false) {
            $decoded = json_decode($value, true);

            if($decoded != null) {
                $ct_options[$key] = $decoded;
                continue;
            }

            $ct_options[$key] = $value;
        }
    }

    return $ct_options;
}

/**
 * Get js keys from plugin settings
 *
 * @param $mod_settings
 * @return null|string
 */
function cleantalk_get_js_keys($mod_settings) {
    if(isset($mod_settings['cleantalk_js_keys'])) {
        $js_keys = json_decode($mod_settings['cleantalk_js_keys'], true);
        if(isset($js_keys['keys'])) {
            return json_encode($js_keys['keys']);
        }
    }

    return null;
}