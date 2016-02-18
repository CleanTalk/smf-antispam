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
define('CT_AGENT_VERSION', 'smf-190');
define('CT_SERVER_URL', 'http://moderate.cleantalk.org');
define('CT_DEBUG', false);


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

    if (defined('CT_DEBUG') && CT_DEBUG) {
        log_error('CleanTalk request: ' . var_export($ct_request, true), 'user');
    }

    /**
     * @var CleantalkResponse $ct_result CleanTalk API call result
     */
    $ct_result = $ct->isAllowUser($ct_request);

    if ($ct_result->errno != 0 && !cleantalk_is_valid_js()) {
        cleantalk_log('deny registration (errno !=0, invalid js test)' . strip_tags($ct_result->comment));
        fatal_error('CleanTalk: ' . strip_tags($ct_result->comment), false);
        return;
    }

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

    if (defined('CT_DEBUG') && CT_DEBUG) {
        log_error('CleanTalk request: ' . var_export($ct_request, true), 'user');
    }

    /**
     * @var CleantalkResponse $ct_result CleanTalk API call result
     */
    $ct_result = $ct->isAllowMessage($ct_request);

    if ($ct_result->errno != 0 && !cleantalk_is_valid_js()) {
        cleantalk_log('deny post (errno !=0, invalid js test)' . strip_tags($ct_result->comment));
        fatal_error('CleanTalk: ' . strip_tags($ct_result->comment), false);
        return;
    }

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
    global $txt;
    $config_vars[] = array('title', 'cleantalk_settings');
    $config_vars[] = array('text', 'cleantalk_api_key');
    $config_vars[] = array('check', 'cleantalk_first_post_checking');
    $config_vars[] = array('check', 'cleantalk_logging');
    $config_vars[] = array('check', 'cleantalk_tell_others', 'postinput' => $txt['cleantalk_tell_others_postinput']);
    $config_vars[] = array('check', 'cleantalk_sfw', 'postinput' => $txt['cleantalk_sfw_postinput']);
    $config_vars[] = array('desc', 'cleantalk_api_key_description');
    $config_vars[] = array('desc', 'cleantalk_check_users');
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
    global $context, $user_info, $modSettings, $smcFunc;
    if (
        isset($context['template_layers']) &&
        is_array($context['template_layers']) &&
        in_array('body', $context['template_layers']) &&
        ($user_info['is_guest'] || $user_info['posts'] == 0) &&
        !cleantalk_is_valid_js()
    ) {
        $context ['html_headers'] .= cleantalk_print_js_input();
    }
    
    if($user_info['is_admin'] && isset($_POST['ct_del_user']))
	{
		foreach($_POST['ct_del_user'] as $key=>$value)
		{
			$result = $smcFunc['db_query']('', 'delete from {db_prefix}members where id_member='.intval($key),Array());
			$result = $smcFunc['db_query']('', 'delete from {db_prefix}topics where id_member_started='.intval($key),Array());
			$result = $smcFunc['db_query']('', 'delete from {db_prefix}messages where id_member='.intval($key),Array());
		}
	}
	
	if($user_info['is_admin'] && isset($_POST['ct_delete_all']))
	{
		$result = $smcFunc['db_query']('', 'select * from {db_prefix}members where ct_marked=1',Array());
		while($row = $smcFunc['db_fetch_assoc'] ($result))
		{
			$tmp = $smcFunc['db_query']('', 'delete from {db_prefix}topics where id_member_started='.$row['id_member'],Array());
			$tmp = $smcFunc['db_query']('', 'delete from {db_prefix}messages where id_member='.$row['id_member'],Array());
		}
		$result = $smcFunc['db_query']('', 'delete from {db_prefix}members where ct_marked=1',Array());
	}

    if (
        isset($context['template_layers']) &&
        $context['template_layers'] === array('html', 'body') &&
        array_key_exists('cleantalk_tell_others', $modSettings) &&
        $modSettings['cleantalk_tell_others']
    ) {
        // add "tell others" templates
        $context['template_layers'][] = 'cleantalk';
    }
    if(isset($_POST['cleantalk_api_key']))
    {
    	 $ct = new Cleantalk();
         $ct->server_url = CT_SERVER_URL;
     
         $ct_request = new CleantalkRequest();
         $ct_request->auth_key = cleantalk_get_api_key();
     
         $ct_request->response_lang = 'en'; // SMF use any charset and language
     
         $ct_request->agent = CT_AGENT_VERSION;
         $ct_request->sender_email = 'good@cleantalk.org';
     
         $ip = isset($user_info['ip']) ? $user_info['ip'] : $_SERVER['REMOTE_ADDR'];
         $ct_request->sender_ip = $ct->ct_session_ip($ip);
     
         $ct_request->sender_nickname = 'CleanTalk';
         $ct_request->message = 'This message is a test to check the connection to the CleanTalk servers.';
     
         $ct_request->submit_time = 10;
     
         $ct_request->js_on = 1;
         $ct_result = $ct->isAllowMessage($ct_request);
         
    }
    if(isset($_POST['cleantalk_sfw']) && $_POST['cleantalk_sfw'] == 1)
    {
    	global $smcFunc;
    	$sql="DROP TABLE IF EXISTS `cleantalk_sfw`";
		$result = $smcFunc['db_query']('', $sql, Array());
		$sql="CREATE TABLE IF NOT EXISTS `cleantalk_sfw` (
`network` int(11) unsigned NOT NULL,
`mask` int(11) unsigned NOT NULL,
INDEX (  `network` ,  `mask` )
) ENGINE = MYISAM ";
		$result = $smcFunc['db_query']('', $sql, Array());
		$data = Array(	'auth_key' => cleantalk_get_api_key(),
				'method_name' => '2s_blacklists_db'
			);
			
		$result=sendRawRequest('https://api.cleantalk.org/2.1',$data,false);
		$result=json_decode($result, true);
		if(isset($result['data']))
		{
			$result=$result['data'];
			$query="INSERT INTO `cleantalk_sfw` VALUES ";
			for($i=0;$i<sizeof($result);$i++)
			{
				if($i==sizeof($result)-1)
				{
					$query.="(".$result[$i][0].",".$result[$i][1].")";
				}
				else
				{
					$query.="(".$result[$i][0].",".$result[$i][1]."), ";
				}
			}
			$result = $smcFunc['db_query']('', $query, Array());
		}
    }
    
    if(isset($modSettings['cleantalk_sfw']) && $modSettings['cleantalk_sfw'] == 1)
    {
    	$is_sfw_check=true;
	   	$ip=CleantalkGetIP();
	   	$ip=array_unique($ip);
	   	$key=cleantalk_get_api_key();
	   	for($i=0;$i<sizeof($ip);$i++)
		{
	    	if(isset($_COOKIE['ct_sfw_pass_key']) && $_COOKIE['ct_sfw_pass_key']==md5($ip[$i].$key))
	    	{
	    		$is_sfw_check=false;
	    		if(isset($_COOKIE['ct_sfw_passed']))
	    		{
	    			@setcookie ('ct_sfw_passed', '0', 1, "/");
	    		}
	    	}
	    }
		if($is_sfw_check)
		{
			include_once("cleantalk-sfw.class.php");
			$sfw = new CleanTalkSFW();
			$sfw->cleantalk_get_real_ip();
			$sfw->check_ip();
			if($sfw->result)
			{
				$sfw->sfw_die();
			}
		}
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
    return array_key_exists('ct_checkjs', $_COOKIE) && $_COOKIE['ct_checkjs'] == cleantalk_get_checkjs_code();
}

/**
 * Above content
 */
function template_cleantalk_above()
{
    //none
}

/**
 * Below content
 */
function template_cleantalk_below()
{
	global $modSettings;
	if(!empty($modSettings['cleantalk_tell_others']))
	{
		$message = '<a href="https://cleantalk.org/smf-anti-spam-mod">SMF spam</a> blocked by CleanTalk';
		echo '<div class="cleantalk_tell_others" style="text-align: center;padding:5px 0;">', $message, '</div>';
	}
}

function cleantalk_buffer($buffer)
{
	global $modSettings, $user_info, $smcFunc;
	if($user_info['is_admin'] && isset($_GET['action']) && $_GET['action'] == 'admin')
	{
		global $forum_version;
		if(strpos($forum_version, 'SMF 2.0')===false)
		{
			$html='';
		}
		else
		{
			$html='<span id="ct_anchor"></span><script>
			document.getElementById("ct_anchor").parentElement.style.height="0px";
			document.getElementById("ct_anchor").parentElement.style.padding="0px";
			document.getElementById("ct_anchor").parentElement.style.border="0px";
			</script>';
		}
		if(isset($_POST['ct_del_user']))
		{
			foreach($_POST['ct_del_user'] as $key=>$value)
			{
				$result = $smcFunc['db_query']('', 'delete from {db_prefix}members where id_member='.intval($key),Array());
			}
		}
		if(isset($_GET['ctcheckspam']))
		{
			$sql = 'UPDATE {db_prefix}members set ct_marked=0';
			$result = $smcFunc['db_query']('', $sql, Array());
			$sql = 'SELECT * FROM {db_prefix}members where passwd<>""';
			$result = $smcFunc['db_query']('', $sql, Array());
			$users=Array();
			$users[0]=Array();
			$data=Array();
			$data[0]=Array();
			$cnt=0;
			while($row = $smcFunc['db_fetch_assoc'] ($result))
			{
				//$html.=serialize($row);
				$users[$cnt][] = Array('name' => $row['member_name'],
									'id' => $row['id_member'],
									'email' => $row['email_address'],
									'ip' => $row['member_ip'],
									'joined' => $row['date_registered'],
									'visit' => $row['last_login'],
							);
				$data[$cnt][]=$row['email_address'];
				$data[$cnt][]=$row['member_ip'];
				if(sizeof($users[$cnt])>450)
				{
					$cnt++;
					$users[$cnt]=Array();
					$data[$cnt]=Array();
				}
			}
			
			$error="";
			
			for($i=0;$i<sizeof($users);$i++)
			{
				$send=implode(',',$data[$i]);
				$req="data=$send";
				$opts = array(
				    'http'=>array(
				        'method'=>"POST",
				        'content'=>$req,
				    )
				);
				$context = stream_context_create($opts);
				$result = @file_get_contents("https://api.cleantalk.org/?method_name=spam_check&auth_key=".cleantalk_get_api_key(), 0, $context);
				$result=json_decode($result);
				if(isset($result->error_message))
				{
					$error=$result->error_message;
				}
				else
				{
					if(isset($result->data))
					{
						foreach($result->data as $key=>$value)
						{
							if($key === filter_var($key, FILTER_VALIDATE_IP))
							{
								if($value->appears==1)
								{
									$sql = 'UPDATE {db_prefix}members set ct_marked=1 where member_ip="'.$key.'"';
									$result = $smcFunc['db_query']('', $sql, Array());
								}
							}
							else
							{
								if($value->appears==1)
								{
									$sql = 'UPDATE {db_prefix}members set ct_marked=1 where email_address="'.$key.'"';
									$result = $smcFunc['db_query']('', $sql, Array());
								}
							}
						}
					}
				}
				
			}
			
			if($error!='')
			{
				$html.='<center><div style="border:2px solid red;color:red;font-size:16px;width:300px;padding:5px;"><b>'.$error.'</b></div><br></center>';
			}
			
		}
		
		$result = $smcFunc['db_query']('', 'select * from {db_prefix}members limit 1',Array());
		$row = $smcFunc['db_fetch_assoc'] ($result);
		if(!isset($row['ct_marked']))
		{
			$sql = 'ALTER TABLE  {db_prefix}members ADD  `ct_marked` INT DEFAULT 0 ';
			$result = $smcFunc['db_query']('', $sql, Array());
		}
		
		$sql = 'SELECT * FROM {db_prefix}members where ct_marked=1';
		$result = $smcFunc['db_query']('', $sql, Array());
		
		if($smcFunc['db_num_rows'] ($result) == 0 && isset($_GET['ctcheckspam']))
		{
			$html.='<center><div><b>No spam users found.</b></div><br><br></center>';
		}
		else if($smcFunc['db_num_rows'] ($result) > 0)
		{
			if(isset($_GET['ctcheckspam']))
			{
				$html.='<center><h3>Done. All users tested via blacklists database, please see result below.</h3><br /><br /></center>';
			}
			$html.='<center><table style="border-color:#666666;" border=1 cellspacing=0 cellpadding=3>
	<thead>
	<tr>
		<th>Select</th>
		<th>Username</th>
		<th>Joined</th>
		<th>E-mail</th>
		<th>IP</th>
		<th>Last visit</th>
	</tr>
	</thead>
	<tbody>';
			$found=false;
			while($row = $smcFunc['db_fetch_assoc'] ($result))
			{
				$found=true;
				$html.="<tr>
				<td><input type='checkbox' name=ct_del_user[".$row['id_member']."] value='1' /></td>
				<td>".$row['member_name']."</td>
				<td>".date("Y-m-d H:i:s",$row['date_registered'])."</td>
				<td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['email_address']."'>".$row['email_address']."</a></td>
				<td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['member_ip']."'>".$row['member_ip']."</a></td>
				<td>".date("Y-m-d H:i:s",$row['last_login'])."</td>
				</tr>";
				
			}
			$html.="</tbody></table><br /><input type=submit name='ct_delete_checked' value='Delete selected'> <input type=submit name='ct_delete_all' value='Delete all'><br />All posts of deleted users will be deleted, too.<br /><br /></center>";
		}
		
		$html.="<center><button style=\"width:20%;\" id=\"check_spam\" onclick=\"location.href=location.href.replace('&finishcheck=1','').replace('&ctcheckspam=1','')+'&ctcheckspam=1';return false;\">Check users for spam</button></center>";
		$buffer = str_replace("%CLEANTALK_CHECK_USERS%", $html, $buffer);
	}

	return $buffer;
}

function CleantalkGetIP()
{
	$result=Array();
	if ( function_exists( 'apache_request_headers' ) )
	{
		$headers = apache_request_headers();
	}
	else
	{
		$headers = $_SERVER;
	}
	if ( array_key_exists( 'X-Forwarded-For', $headers ) )
	{
		$the_ip=explode(",", trim($headers['X-Forwarded-For']));
		$result[] = trim($the_ip[0]);
	}
	if ( array_key_exists( 'HTTP_X_FORWARDED_FOR', $headers ))
	{
		$the_ip=explode(",", trim($headers['HTTP_X_FORWARDED_FOR']));
		$result[] = trim($the_ip[0]);
	}
	$result[] = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );

	if(isset($_GET['sfw_test_ip']))
	{
		$result[]=$_GET['sfw_test_ip'];
	}
	return $result;
}