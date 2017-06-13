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

require_once(dirname(__FILE__) . '/Cleantalk.php');
require_once(dirname(__FILE__) . '/CleantalkRequest.php');
require_once(dirname(__FILE__) . '/CleantalkResponse.php');
require_once(dirname(__FILE__) . '/CleantalkHelper.php');
require_once(dirname(__FILE__) . '/CleantalkSFW.php');

// define same CleanTalk options
define('CT_AGENT_VERSION', 'smf-210');
define('CT_SERVER_URL', 'http://moderate.cleantalk.org');
define('CT_DEBUG', false);

/**
 * CleanTalk SFW check
 * @param array $regOptions
 * @param array $theme_vars
 * @return void
 */
function cleantalk_sfw_check()
{	
	global $modSettings, $user_info;
		
	if(!empty($modSettings['cleantalk_sfw']) && !$user_info['is_admin']){
				
		$sfw = new cleantalk\antispam\CleantalkSFW();
		$key = $modSettings['cleantalk_api_key'];
		
		$ips = $sfw->cleantalk_get_real_ip();

		$is_sfw_check=true;
		foreach($ips as $curr_ip){
			
			if(isset($_COOKIE['ct_sfw_pass_key']) && $_COOKIE['ct_sfw_pass_key'] == md5($curr_ip.$key)){
				
				$is_sfw_check=false;
				if(!empty($_COOKIE['ct_sfw_passed'])){
					$sfw->sfw_update_logs($sfw->passed_ip, 'passed');
					setcookie ('ct_sfw_passed', '0', 1, "/");
				}
			}
		}
		if($is_sfw_check){
			$sfw->check_ip();
			if($sfw->result){
				$sfw->sfw_update_logs($sfw->blocked_ip, 'blocked');
				$sfw->sfw_die($key);
			}else{
				setcookie ('ct_sfw_pass_key', md5($sfw->passed_ip.$key), 0, "/");
			}
		}
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

    if (SMF == 'SSI')
		return;

    if ($regOptions['interface'] == 'admin')
        return;

    $ct = new cleantalk\antispam\Cleantalk();
    $ct->server_url = CT_SERVER_URL;

    $ct_request = new cleantalk\antispam\CleantalkRequest();
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
            'REFFERRER'              => isset($_SERVER['HTTP_REFERER'])      ? $_SERVER['HTTP_REFERER']     : null,
            'cms_lang'               => substr($language, 0, 2),                                            
            'USER_AGENT'             => isset($_SERVER['HTTP_USER_AGENT'])   ? $_SERVER['HTTP_USER_AGENT']  : null,
			'js_timezone'            => !empty($_COOKIE['ct_timezone'])      ? $_COOKIE['ct_timezone']      : null,
			'mouse_cursor_positions' => !empty($_COOKIE['ct_pointer_data'])  ? $_COOKIE['ct_pointer_data']  : null,
			'key_press_timestamp'    => !empty($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : null,
			'page_set_timestamp'     => !empty($_COOKIE['ct_ps_timestamp'])  ? $_COOKIE['ct_ps_timestamp']  : null
        )
    );

    if (defined('CT_DEBUG') && CT_DEBUG)
        log_error('CleanTalk request: ' . var_export($ct_request, true), 'user');

    /**
     * @var CleantalkResponse $ct_result CleanTalk API call result
     */
    $ct_result = $ct->isAllowUser($ct_request);

    if($ct_result->errno != 0 && !cleantalk_is_valid_js())
	{
        cleantalk_log('deny registration (errno !=0, invalid js test)' . strip_tags($ct_result->comment));
        fatal_error('CleanTalk: ' . strip_tags($ct_result->comment), false);
        return;
    }

    if($ct_result->inactive == 1)
	{
        // need admin approval

        cleantalk_log('need approval for "' . $regOptions['username'] . '"');

        $regOptions['register_vars']['is_activated'] = 3; // waiting for admin approval
        $regOptions['require'] = 'approval';

		// temporarly turn on notify for new registration
        if (!isset($modSettings['notify_new_registration']) || empty($modSettings['notify_new_registration']))
            $modSettings['notify_new_registration'] = 1;

        // add Cleantalk message to email template
        $user_info['cleantalkmessage'] = $ct_result->comment;

        // temporarly turn on registration_method to approval_after
        $modSettings['registration_method'] = 2;
        return;
    }

    if ($ct_result->allow == 0){
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
function cleantalk_check_message(&$msgOptions, $topicOptions, $posterOptions){
	
    global $language, $user_info, $modSettings, $smcFunc, $db_connection;

    if (SMF == 'SSI') {
		return;
    }

    if(!$modSettings['cleantalk_first_post_checking']){
        return;
    }elseif (isset($user_info['posts']) && $user_info['posts'] > 0){
        return;
    }

    $ct = new cleantalk\antispam\Cleantalk();
    $ct->server_url = CT_SERVER_URL;

    $ct_request = new cleantalk\antispam\CleantalkRequest();
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
            'REFFERRER'              => isset($_SERVER['HTTP_REFERER'])      ? $_SERVER['HTTP_REFERER']     : null,
            'cms_lang'               => substr($language, 0, 2),                                            
            'USER_AGENT'             => isset($_SERVER['HTTP_USER_AGENT'])   ? $_SERVER['HTTP_USER_AGENT']  : null,
			'js_timezone'            => isset($_COOKIE['ct_timezone'])       ? $_COOKIE['ct_timezone']      : null,
			'mouse_cursor_positions' => isset($_COOKIE['ct_pointer_data'])   ? $_COOKIE['ct_pointer_data']  : null,
			'key_press_timestamp'    => !empty($_COOKIE['ct_fkp_timestamp']) ? $_COOKIE['ct_fkp_timestamp'] : null,
			'page_set_timestamp'     => !empty($_COOKIE['ct_ps_timestamp'])  ? $_COOKIE['ct_ps_timestamp']  : null
        )
    );

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
    $ct_answer_text = 'CleanTalk: ' . strip_tags($ct_result->comment);

    if($ct_result->errno != 0 && !cleantalk_is_valid_js()){
        cleantalk_log('deny post (errno !=0, invalid js test)' . strip_tags($ct_result->comment));
        fatal_error($ct_answer_text, false);
        return;
    }

    if ($ct_result->allow == 0){
		$msgOptions['cleantalk_check_message_result'] = $ct_result->comment;
		if ($modSettings['postmod_active']){
            if ($ct_result->stop_queue == 1){
                cleantalk_log('spam message "' . $ct_result->comment . '"');
                fatal_error($ct_answer_text, false);
            }else{
                // If post moderation active then set message not approved
                cleantalk_log('to postmoderation "' . $ct_result->comment . '"');
                $msgOptions['approved'] = 0;
            }
        }else{
            cleantalk_log('spam message "' . $ct_result->comment . '"');
            fatal_error($ct_answer_text, false);
        }
    }else{
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
function cleantalk_after_create_topic($msgOptions, $topicOptions, $posterOptions){
	
    global $sourcedir, $scripturl;

    if (SMF == 'SSI'){
		return;
    }

    if (isset($msgOptions['cleantalk_check_message_result'])){
		
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
function cleantalk_get_checkjs_code(){
	
    global $webmaster_email, $modSettings;
	
	$api_key = isset($modSettings['cleantalk_api_key']) ? $modSettings['cleantalk_api_key'] : null;
	$js_keys = isset($modSettings['cleantalk_js_keys']) ? json_decode($modSettings['cleantalk_js_keys'], true) : null;
	
	if($js_keys == null){
		
		$js_key = strval(md5($api_key . $webmaster_email . time()));
		
		$js_keys = array(
			'keys' => array(
				array(
					time() => $js_key
				)
			), // Keys to do JavaScript antispam test 
			'js_keys_amount' => 24, // JavaScript keys store days - 8 days now
			'js_key_lifetime' => 86400, // JavaScript key life time in seconds - 1 day now
		);
		
	}else{
		
		$keys_times = array();
		
		foreach($js_keys['keys'] as $time => $key){
			
			if($time + $js_keys['js_key_lifetime'] < time())
				unset($js_keys['keys'][$time]);
			
			$keys_times[] = $time;

		}unset($time, $key);
		
		if(max($keys_times) + 3600 < time()){
			$js_key =  strval(md5($api_key . $webmaster_email . time()));
			$js_keys['keys'][time()] = $js_key;
		}else{
			$js_key = $js_keys['keys'][max($keys_times)];
		}
		
	}
	
	updateSettings(array('cleantalk_js_keys' => json_encode($js_keys)), false);	
	
	return $js_key;	
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
 * Add CleanTalk setting into admin panel
 * @param array $config_vars
 */
function cleantalk_general_mod_settings(&$config_vars){
	
    global $txt;
	
    $config_vars[] = array('title', 'cleantalk_settings');
    $config_vars[] = array('text',  'cleantalk_api_key');
    $config_vars[] = array('check', 'cleantalk_first_post_checking');
    $config_vars[] = array('check', 'cleantalk_logging');
    $config_vars[] = array('check', 'cleantalk_tell_others', 'postinput' => $txt['cleantalk_tell_others_postinput']);
    $config_vars[] = array('check', 'cleantalk_sfw', 'postinput' => $txt['cleantalk_sfw_postinput']);
	$config_vars[] = array('desc',  'cleantalk_api_key_description');
    $config_vars[] = array('desc',  'cleantalk_check_users');
}

/**
 * Return CleanTalk javascript verify code
 */
function cleantalk_print_js_input()
{
	
    $value = cleantalk_get_checkjs_code();
	
	return '<script type="text/javascript">
		var d = new Date(), 
			ctTimeMs = new Date().getTime(),
			ctMouseEventTimerFlag = true, //Reading interval flag
			ctMouseData = "[",
			ctMouseDataCounter = 0;
		
		function ctSetCookie(c_name, value) {
			document.cookie = c_name + "=" + encodeURIComponent(value) + "; path=/";
		}
		
		ctSetCookie("ct_ps_timestamp", Math.floor(new Date().getTime()/1000));
		ctSetCookie("ct_fkp_timestamp", "0");
		ctSetCookie("ct_pointer_data", "0");
		ctSetCookie("ct_timezone", "0");
		
		setTimeout(function(){
			ctSetCookie("ct_timezone", d.getTimezoneOffset()/60*(-1));
			ctSetCookie("ct_checkjs", "'.$value.'");
		},1000);
		
		//Reading interval
		var ctMouseReadInterval = setInterval(function(){
				ctMouseEventTimerFlag = true;
			}, 150);
			
		//Writting interval
		var ctMouseWriteDataInterval = setInterval(function(){
				var ctMouseDataToSend = ctMouseData.slice(0,-1).concat("]");
				ctSetCookie("ct_pointer_data", ctMouseDataToSend);
			}, 1200);
		
		//Stop observing function
		function ctMouseStopData(){
			if(typeof window.addEventListener == "function")
				window.removeEventListener("mousemove", ctFunctionMouseMove);
			else
				window.detachEvent("onmousemove", ctFunctionMouseMove);
			clearInterval(ctMouseReadInterval);
			clearInterval(ctMouseWriteDataInterval);				
		}
		
		//Logging mouse position each 300 ms
		var ctFunctionMouseMove = function output(event){
			if(ctMouseEventTimerFlag == true){
				var mouseDate = new Date();
				ctMouseData += "[" + Math.round(event.pageY) + "," + Math.round(event.pageX) + "," + Math.round(mouseDate.getTime() - ctTimeMs) + "],";
				ctMouseDataCounter++;
				ctMouseEventTimerFlag = false;
				if(ctMouseDataCounter >= 100)
					ctMouseStopData();
			}
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
		
		//Writing first key press timestamp
		var ctFunctionFirstKey = function output(event){
			var KeyTimestamp = Math.floor(new Date().getTime()/1000);
			ctSetCookie("ct_fkp_timestamp", KeyTimestamp);
			ctKeyStopStopListening();
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
        $context ['html_headers'] .= cleantalk_print_js_input();
    }

	// Getting key automatically
	if(isset($_GET['ctgetautokey'])){
		
		$result = cleantalk\antispam\CleantalkHelper::getAutoKey($user_info['email'], $_SERVER['SERVER_NAME'], 'smf', 'antispam');
		
		if (empty($result['error'])){
			
			updateSettings(array('cleantalk_api_key_is_ok' => '1'), false);
			updateSettings(array('cleantalk_api_key' => $result['auth_key']), false);
			
			// Doing noticePaidTill(), sfw update and sfw send logs via cron
			$modSettings['cleantalk_api_key'] = $result['auth_key'];
			$modSettings['cleantalk_api_key_is_ok'] = 1;
			$modSettings['cleantalk_last_account_check'] = time()-10;
			$modSettings['cleantalk_sfw_last_update'] = time()-10;
			$modSettings['cleantalk_sfw_last_update'] = time()-10;

			// User token is empty, request it via noticePaidTill()
			if (empty($result['user_token'])){
				$result = cleantalk\antispam\CleantalkHelper::noticePaidTill($result['auth_key']);
				if (empty($result['error']))
					updateSettings(array('cleantalk_user_token' => $result['user_token']), false);
			}
			
		}
	}
	
	// Check if key is valid
	if(isset($_POST['cleantalk_api_key']) && $_POST['cleantalk_api_key'] != $modSettings['cleantalk_api_key']){
		
		$key_to_validate = strval($_POST['cleantalk_api_key']);
		
		$result = cleantalk\antispam\CleantalkHelper::noticeValidateKey($key_to_validate);
		
		if(empty($result['error'])){
			
			if($result && isset($result['valid']) && intval($result['valid']) == 1){
				updateSettings(array('cleantalk_api_key_is_ok' => '1', false));
				
				// If key is valid doing noticePaidTill(), sfw update and sfw send logs via cron
				$modSettings['cleantalk_api_key'] = $key_to_validate;
				$modSettings['cleantalk_api_key_is_ok'] = 1;
				$modSettings['cleantalk_last_account_check'] = time()-10;
				$modSettings['cleantalk_sfw_last_update'] = time()-10;
				$modSettings['cleantalk_sfw_last_update'] = time()-10;
			}
			else
				updateSettings(array('cleantalk_api_key_is_ok' => '0', false));
			
		}
		
		
	}
	
    if($user_info['is_admin'] && isset($_POST['ct_del_user'])){	
		
		checkSession('request');
		
		if (!isset($db_connection) || $db_connection === false)
		    loadDatabase();
		
		if (isset($db_connection) && $db_connection != false){
		    foreach($_POST['ct_del_user'] as $key=>$value){
				
				$result = $smcFunc['db_query']('', 'delete from {db_prefix}members where id_member='.intval($key),Array('db_error_skip' => true));
				$result = $smcFunc['db_query']('', 'delete from {db_prefix}topics where id_member_started='.intval($key),Array('db_error_skip' => true));
				$result = $smcFunc['db_query']('', 'delete from {db_prefix}messages where id_member='.intval($key),Array('db_error_skip' => true));
				
		    }
		}
    }

    if($user_info['is_admin'] && isset($_POST['ct_delete_all'])){
		
		checkSession('request');
		
		if (!isset($db_connection) || $db_connection === false)
		    loadDatabase();
		
		if (isset($db_connection) && $db_connection != false){
			
		    $result = $smcFunc['db_query']('', 'select * from {db_prefix}members where ct_marked=1',Array());
			
		    while($row = $smcFunc['db_fetch_assoc'] ($result)){
				$tmp = $smcFunc['db_query']('', 'delete from {db_prefix}topics where id_member_started='.$row['id_member'],Array('db_error_skip' => true));
				$tmp = $smcFunc['db_query']('', 'delete from {db_prefix}messages where id_member='.$row['id_member'],Array('db_error_skip' => true));
		    }
			
		    $result = $smcFunc['db_query']('', 'delete from {db_prefix}members where ct_marked=1',Array('db_error_skip' => true));
		}
    }

	// add "tell others" templates
    if (isset($context['template_layers'])
        && $context['template_layers'] === array('html', 'body')
        && array_key_exists('cleantalk_tell_others', $modSettings)
        && $modSettings['cleantalk_tell_others']
    ){
        $context['template_layers'][] = 'cleantalk';
	}
	
    if($user_info['is_admin'] && isset($_POST['cleantalk_api_key'])){

		checkSession('request');

    	$ct = new cleantalk\antispam\Cleantalk();
        $ct->server_url = CT_SERVER_URL;
     
        $ct_request = new cleantalk\antispam\CleantalkRequest();
        $ct_request->auth_key = cleantalk_get_api_key();
		$ct_request->feedback = '0:'.CT_AGENT_VERSION;
		
		$ct_result = $ct->sendFeedback($ct_request);		
    }
	
	/* Update SFW and send logs if settings seved */
    if($user_info['is_admin'] && isset($_POST['cleantalk_sfw']) && (int)$_POST['cleantalk_sfw'] == 1){

		$sfw = new cleantalk\antispam\CleantalkSFW;
		$sfw->sfw_update($modSettings['cleantalk_api_key']);
		$sfw->send_logs($modSettings['cleantalk_api_key']);
		unset($sfw);
		updateSettings(array('cleantalk_sfw_last_update' => time()+86400), false);
		updateSettings(array('cleantalk_sfw_last_logs_sent' => time()+3600), false);
		
    }
	
	/* Cron for update SFW */
	if(!empty($modSettings['cleantalk_api_key_is_ok']) && !empty($modSettings['cleantalk_sfw']) && isset($modSettings['cleantalk_sfw_last_update']) && $modSettings['cleantalk_sfw_last_update'] < time()){

		$sfw = new cleantalk\antispam\CleantalkSFW;
		$sfw->sfw_update($modSettings['cleantalk_api_key']);
		unset($sfw);
		updateSettings(array('cleantalk_sfw_last_update' => time()+86400), false);
		
	}
	
	/* Cron for send SFW logs */
	if(!empty($modSettings['cleantalk_api_key_is_ok']) && !empty($modSettings['cleantalk_sfw']) && isset($modSettings['cleantalk_sfw_last_logs_sent']) && $modSettings['cleantalk_sfw_last_logs_sent'] < time()){
		
		$sfw = new cleantalk\antispam\CleantalkSFW;
		$sfw->send_logs($modSettings['cleantalk_api_key']);
		unset($sfw);
		updateSettings(array('cleantalk_sfw_last_logs_sent' => time()+3600), false);
		
	}
	
	/* Cron for account status */
	if(!empty($modSettings['cleantalk_api_key_is_ok']) && isset($modSettings['cleantalk_last_account_check']) && $modSettings['cleantalk_last_account_check'] < time()){
		
		$result = cleantalk\antispam\CleantalkHelper::noticePaidTill($modSettings['cleantalk_api_key']);
		
		if(empty($result['error'])){
			$settings_array = array(
				'cleantalk_show_notice' => $result['show_notice'],
				'cleantalk_renew'       => $result['renew'],      
				'cleantalk_trial'       => $result['trial'],      
				'cleantalk_user_token'  => $result['user_token'], 
				'cleantalk_spam_count'  => $result['spam_count'], 
				'cleantalk_moderate_ip' => $result['moderate_ip'],
				'cleantalk_show_review' => $result['show_review'],
				'cleantalk_ip_license'  => $result['ip_license'],
				'cleantalk_last_account_check'   => time()+86400
			);
		}else{
			$settings_array = array(
				'cleantalk_last_account_check'   => time()+3600
			);
		}
		
		updateSettings($settings_array, false);
		
	}
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
 * Is Javascript enabled and valid
 * @return bool
 */
function cleantalk_is_valid_js()
{
	if(isset($_COOKIE['ct_checkjs']) && $_COOKIE['ct_checkjs']){
				
		global $modSettings;
		
		$js_keys = isset($modSettings['cleantalk_js_keys']) ? json_decode($modSettings['cleantalk_js_keys'], true) : null;
				
		if($js_keys){
			$result = in_array($_COOKIE['ct_checkjs'], $js_keys['keys']);
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
	global $user_info, $modSettings, $txt;
	
	if($user_info['is_admin'] && isset($_GET['action']) && $_GET['action'] == 'admin'){
		
		$source_dir = (empty($_SERVER['HTTPS']) ? 'http://' : 'https://') . $_SERVER['HTTP_HOST'] . '/Sources/Cleantalk/';
		
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
			if(empty($modSettings['cleantalk_api_key_is_ok']) && isset($_GET['area']) && $_GET['area'] != 'modsettings'){
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

	if($user_info['is_admin'] && isset($_GET['action'], $_GET['area']) && $_GET['action'] == 'admin' && $_GET['area'] == 'modsettings'){
		
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
			
			db_extend('packages');
			
		    $cols = $smcFunc['db_list_columns'] ('{db_prefix}members', 0);
			
		    if(in_array('ct_marked', $cols)){
				
				if(isset($_GET['ctcheckspam'])){
					$sql = 'UPDATE {db_prefix}members set ct_marked=0';
					$result = $smcFunc['db_query']('', $sql, Array());
					$sql = 'SELECT * FROM {db_prefix}members where passwd<>""';
					$result = $smcFunc['db_query']('', $sql, Array());
					$users=Array();
					$users[0]=Array();
					$data=Array();
					$data[0]=Array();
					$cnt=0;
					while($row = $smcFunc['db_fetch_assoc'] ($result)){
							
						$users[$cnt][] = array(
							'name' => $row['member_name'],
							'id' => $row['id_member'],
							'email' => $row['email_address'],
							'ip' => $row['member_ip'],
							'joined' => $row['date_registered'],
							'visit' => $row['last_login'],
						);
						
						$data[$cnt][]=$row['email_address'];
						$data[$cnt][]=$row['member_ip'];
						
						if(sizeof($users[$cnt])>450){
							$cnt++;
							$users[$cnt]=Array();
							$data[$cnt]=Array();
						}
					}
				
					$error="";
				
					for($i=0;$i<sizeof($users);$i++){
						$send=implode(',',$data[$i]);
						$req="data=$send";
						$opts = array(
							'http'=>array(
								'method'=>"POST",
								'content'=>$req,
							)
						);
						
						$context = stream_context_create($opts);
						$result = @file_get_contents("https://api.cleantalk.org/?method_name=spam_check_cms&auth_key=".cleantalk_get_api_key(), 0, $context);
						$result=json_decode($result);
						if(isset($result->error_message)){
							$error=$result->error_message;
						}else{
							
							if(isset($result->data)){
								
								foreach($result->data as $key=>$value){
									
									if($key === filter_var($key, FILTER_VALIDATE_IP)){
										
										if($value->appears==1){
											
											$sql = 'UPDATE {db_prefix}members set ct_marked=1 where member_ip="'.$key.'"';
											$result = $smcFunc['db_query']('', $sql, Array('db_error_skip' => true));
										}
										
									}else{
										
										if($value->appears==1){
											$sql = 'UPDATE {db_prefix}members set ct_marked=1 where email_address="'.$key.'"';
											$result = $smcFunc['db_query']('', $sql, Array('db_error_skip' => true));
										}
									}
								}
							}
						}
					}
				
					if($error!='')
						$html.='<center>'
									.'<div style="border:2px solid red;color:red;font-size:16px;width:300px;padding:5px;">'
										.'<b>'.$error.'</b>'
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
					
					if($pages && $pages != 1){
						$html.= "<div style='margin: 10px;'>"
								."<b>".$txt['cleantalk_check_users_pages'].":</b>"
								."<ul style='display: inline-block; margin: 0; padding: 0;'>";
									for($i = 1; $i <= $pages; $i++){
										$html.= "<li style='display: inline-block;	margin-left: 10px;'>"
												."<a href='".preg_replace('/(&ctcheckspam=.*|&spam_page=.*)/', '', $_SERVER['REQUEST_URI'])."&spam_page=$i'>"
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
						<td>{$row['member_name']}<sup><a href='index.php?action=profile;u={$row['id_member']}' target='_blank'>Details</a></sup></td>
						<td>".date("Y-m-d H:i:s",$row['date_registered'])."</td>
						<td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['email_address']."'><img src='https://cleantalk.org/images/icons/external_link.gif' border='0'/> ".$row['email_address']."</a></td>
						<td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['member_ip']."'><img src='https://cleantalk.org/images/icons/external_link.gif' border='0'/> ".$row['member_ip']."</a></td>
						<td>".date("Y-m-d H:i:s", $row['last_login'])."</td>
						<td>".$row['posts']."</td>
						</tr>";
						
					}
					
					$html.="</tbody></table></center>";
					
					if($pages && $pages != 1){
						$html.= "<div style='margin: 10px;'>"
								."<b>".$txt['cleantalk_check_users_pages'].":</b>"
								."<ul style='display: inline-block; margin: 0; padding: 0;'>";
									for($i = 1; $i <= $pages; $i++){
										$html.= "<li style='display: inline-block;	margin-left: 10px;'>"
												."<a href='".preg_replace('/(&ctcheckspam=.*|&spam_page=.*)/', '', $_SERVER['REQUEST_URI'])."&spam_page=$i'>"
													.($i == $page ? "<span style='font-size: 1.1em; font-weight: 600;'>$i</span>" : $i)
												."</a>"
											."</li>";
									}
							$html.= "</ul>";
						$html.= "</div>";
					}
					
					$html.="<br /><center><input type=submit name='ct_delete_checked' value='".$txt['cleantalk_check_users_tbl_delselect']."' onclick='return confirm(\"".$txt['cleantalk_check_users_confirm']."\")'> <input type=submit name='ct_delete_all' value='".$txt['cleantalk_check_users_tbl_delall']."' onclick='return confirm(\"".$txt['cleantalk_check_users_confirm']."\")'><br />".$txt['cleantalk_check_users_tbl_delnotice']."<br /><br /></center>";
				}
		    }
		
		    $html.="<center><button style=\"width:20%;\" id=\"check_spam\" onclick=\"location.href=location.href.replace('&finishcheck=1','').replace('&ctcheckspam=1','').replace('&ctgetautokey=1','')+'&ctcheckspam=1';return false;\">".$txt['cleantalk_check_users_button']."</button><br /><br />".$txt['cleantalk_check_users_button_after']."</center>";
		}
		$buffer = str_replace("%CLEANTALK_CHECK_USERS%", $html, $buffer);
		
	// Key auto getting, Key buttons, Control panel button 
		
		$cleantalk_key_html = '';
		
		if(!isset($modSettings['cleantalk_api_key']))
			$modSettings['cleantalk_api_key'] == '';
		
		$cleantalk_key_html .= '<input type="text" name="cleantalk_api_key" id="cleantalk_api_key" value="'.$modSettings['cleantalk_api_key'].'" class="input_text">';
		
		if(!isset($modSettings['cleantalk_api_key_is_ok'])){
			
			$result = cleantalk\antispam\CleantalkHelper::noticeValidateKey($modSettings['cleantalk_api_key']);		
			$result = ($result != false ? json_decode($result, true): null);
			
			if($result && isset($result['valid']) && $result['valid'] == '1')
				updateSettings(array('cleantalk_api_key_is_ok' => '1'), true);
			else
				updateSettings(array('cleantalk_api_key_is_ok' => '0'), true);
		}
		
		if($modSettings['cleantalk_api_key_is_ok'] == '0' || $modSettings['cleantalk_api_key'] == ''){
			
			$cleantalk_key_html .= "&nbsp<span style='color: red;'>".$txt['cleantalk_key_not_valid']."</span>";
			$cleantalk_key_html .= "<br><br><a target='_blank' href='https://cleantalk.org/register?platform=smf&email=".urlencode($user_info['email'])."&website=".urlencode($_SERVER['SERVER_NAME'])."&product_name=antispam'>
					<input type='button' value='".$txt['cleantalk_get_access_manually']."' />
				</a> or ";
			$cleantalk_key_html .= '<input name="spbc_get_apikey_auto" type="submit" class="spbc_manual_link" value="'.$txt['cleantalk_get_access_automatically'].'" onclick="location.href=location.href.replace(\'&finishcheck=1\',\'\').replace(\'&ctcheckspam=1\',\'\').replace(\'&ctgetautokey=1\',\'\')+\'&ctgetautokey=1\';return false;"/>';
			$cleantalk_key_html .= "<br/><br/>";
			$cleantalk_key_html .= "<div style='font-size: 10pt; color: #666 !important'>" . sprintf($txt['cleantalk_admin_email_will_be_used'], $user_info['email']) . "</div>";
			$cleantalk_key_html .= "<div style='font-size: 10pt; color: #666 !important'><a target='__blank' style='color:#BBB;' href='https://cleantalk.org/publicoffer'> ".$txt['cleantalk_license_agreement']." </a></div><br><br>";
			
		}else{
			
			$cleantalk_key_html .= "&nbsp<span style='color: green;'>".$txt['cleantalk_key_valid']."</span>";
			$cleantalk_key_html .= '<br><br><a target="_blank" href="https://cleantalk.org/my?user_token='.$modSettings['cleantalk_user_token'].'&cp_mode=antispam" style="display: inline-block;"><input type="button" value="'.$txt['cleantalk_get_statistics'].'"></a><br><br>';
			
		}
		
		$buffer = preg_replace('/<input type="text" name="cleantalk_api_key" id="cleantalk_api_key" value="[\da-zA-Z]{0,}" class="input_text" \/>/', $cleantalk_key_html, $buffer, 1);
		
	}
	
	return $buffer;
}
