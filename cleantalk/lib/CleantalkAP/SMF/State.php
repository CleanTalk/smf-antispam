<?php

namespace CleantalkAP\Common;

/*
 * 
 * CleanTalk Security State class
 * 
 * @package Security Plugin by CleanTalk
 * @subpackage State
 * @Version 2.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

class State
{
	public $option_prefix = '';
	public $storage = array();
	
	public $default_settings = array();
	public $default_data = array(
		
		'plugin_version'           => 1.0,
		
		'account' => array(
			// Notices
			'show_notice'     => 0,
			'show_review'     => 0,
			'renew'           => 0,
			'trial'           => 0,
			'update'          => 0,
			// Account params
			'moderate_ip'     => 0,
			'moderate'        => 0,
			'valid'           => 0,
			'ip_license'      => 0,
			'service_id'      => 0,
			'license_trial'   => 0,
			// Display stuff
			'spam_count'      => 0,
			'account_name_ob' => '',
			// Misc
			'user_token'      => '',
		),
		
		'stats' => array(
			'fw_log_sent_time',
			'fw_log_sent_amount',
			'fw_entries',
			'fw_updated_time',
			'fw_networks_amount',
			'events_log_sent_time',
			'events_log_sent_amount',
			'events_entries',
			'fw_logs_last_sent',
			'fw_logs_last_sent',
			'php_log_sent_amount' => 0,
			'php_log_sent_time' => 0,
		),
		
		'status' => array(
			'key_is_ok'                => false,
		),
		
		'salt'                     => '',
		
	);
	public $def_network_settings = array(
		'allow_custom_key'   => false,
		'allow_cleantalk_cp' => false,
		'key_is_ok'          => false,
		'spbc_key'           => '',
		'user_token'         => '',
		'service_id'         => '',
		'moderate'           => 0
	);
	
	public $def_remote_calls = array(
		
	// Common
		'close_renew_banner'       => array('last_call' => 0,),
		'update_plugin'            => array('last_call' => 0,),
		'update_security_firewall' => array('last_call' => 0, 'cooldown' => 3),
		'drop_security_firewall'   => array('last_call' => 0,),
		'update_settings'          => array('last_call' => 0,),
		
	// Inner
		'download__quarantine_file' => array('last_call' => 0, 'cooldown' => 3),
		
	// Backups
		'backup_signatures_files' => array('last_call' => 0,),
		'rollback_repair'         => array('last_call' => 0,),
		
	// Scanner
		'scanner_signatures_update'        => array('last_call' => 0,),
		'scanner_clear_hashes'             => array('last_call' => 0,),
		
		'scanner__controller'              => array('last_call' => 0, 'cooldown' => 3),
		'scanner__get_remote_hashes'       => array('last_call' => 0,),
		'scanner__count_hashes_plug'       => array('last_call' => 0,),
		'scanner__get_remote_hashes__plug' => array('last_call' => 0,),
		'scanner__clear_table'             => array('last_call' => 0,),
		'scanner__count_files'             => array('last_call' => 0,),
		'scanner__scan'                    => array('last_call' => 0,),
		'scanner__count_files__by_status'  => array('last_call' => 0,),
		'scanner__scan_heuristic'          => array('last_call' => 0,),
		'scanner__scan_signatures'         => array('last_call' => 0,),
		'scanner__count_cure'              => array('last_call' => 0,),
		'scanner__cure'                    => array('last_call' => 0,),
		'scanner__links_count'             => array('last_call' => 0,),
		'scanner__links_scan'              => array('last_call' => 0,),
		'scanner__frontend_scan'           => array('last_call' => 0,),
	);
	
	public $def_errors = array();
	
	public function __construct($option_prefix, $options = array('settings'), $wpms = false)
	{
		$this->option_prefix = $option_prefix;
		
		if($wpms){
			$option = get_site_option($this->option_prefix.'_network_settings');			
			$option = is_array($option) ? $option : $this->def_network_settings;
			$this->network_settings = new \ArrayObject($option);
		}
		
		foreach($options as $option_name){
			
			$option = get_option($this->option_prefix.'_'.$option_name);
			
			// Default options
			if($this->option_prefix.'_'.$option_name === 'spbc_settings'){
				$option = is_array($option) ? array_merge($this->default_settings, $option) : $this->default_settings;
				if(!is_main_site()) $option['backend_logs_enable'] = 0;
			}
			
			// Default data
			if($this->option_prefix.'_'.$option_name === 'spbc_data'){
				$option = is_array($option) ? array_merge($this->default_data,     $option) : $this->default_data;
				if(empty($option['salt'])) $option['salt'] = str_pad(rand(0, getrandmax()), 6, '0').str_pad(rand(0, getrandmax()), 6, '0');
				if(empty($option['last_php_log_sent'])) $option['last_php_log_sent'] = time();
			}
			
			// Default errors
			if($this->option_prefix.'_'.$option_name === 'spbc_errors'){
				$option = is_array($option) ? array_merge($this->def_errors, $option) : $this->def_errors;
			}
			
			// Default remote calls
			if($this->option_prefix.'_'.$option_name === 'spbc_remote_calls'){
				$option = is_array($option) ? array_merge($this->def_remote_calls, $option) : $this->def_remote_calls;
			}
			
			$this->$option_name = is_array($option) ? new \ArrayObject($option) : $option;
			
		}
	}
	
	private function getOption($option_name)
	{
		$option = get_option('spbc_'.$option_name);
		$this->$option_name = gettype($option) === 'array'
			? new \ArrayObject($option)
			: $option;
	}
	
	/**
	 * @param string $option_name
	 * @param bool $use_perfix
	 * @param bool $autoload
	 */
	public function save($option_name, $use_perfix = true, $autoload = true)
	{	
		$option_name_to_save = $use_perfix ? $this->option_prefix.'_'.$option_name : $option_name;
		$arr = array();
		foreach($this->$option_name as $key => $value){
			$arr[$key] = $value;
		}
		update_option($option_name_to_save, $arr, $autoload);
	}
	
	public function saveSettings()
	{
		update_option($this->option_prefix.'_settins', $this->settings);
	}
	
	public function saveData()
	{		
		update_option($this->option_prefix.'_data', $this->data);
	}
	
	public function saveNetworkSettings()
	{		
		update_site_option($this->option_prefix.'_network_settings', $this->network_settings);
	}
	
	public function deleteOption($option_name, $use_prefix = false)
	{
		if($this->__isset($option_name)){
			$this->__unset($option_name);
			delete_option( ($use_prefix ? $this->option_prefix.'_' : '') . $option_name);
		}		
	}
	
	/**
	 * Prepares an adds an error to the plugin's data
	 *
	 * @param string type
	 * @param mixed array || string
	 * @returns null
	 */
	public function error_add($type, $error, $major_type = null, $set_time = true)
	{
		$error = is_array($error)
			? $error['error']
			: $error;
		
		// Exceptions
		if( ($type == 'send_logs'          && $error == 'NO_LOGS_TO_SEND') ||
			($type == 'send_firewall_logs' && $error == 'NO_LOGS_TO_SEND') ||
			$error == 'LOG_FILE_NOT_EXISTS'
		)
			return;
		
		$error = array(
			'error'      => $error,
			'error_time' => $set_time ? current_time('timestamp') : null,
		);
		
		if(!empty($major_type)){
			$this->errors[$major_type][$type] = $error;
		}else{
			$this->errors[$type] = $error;
		}
		
		$this->save('errors');
	}
	
	/**
	 * Deletes an error from the plugin's data
	 *
	 * @param string $type
	 * @param bool   $save_flag
	 * @param string $major_type
	 *
	 * @return void
	 */
	public function error_delete($type, $save_flag = false, $major_type = null)
	{
		if(is_string($type))
			$type = explode(' ', $type);
		
		foreach($type as $val){
			if($major_type){
				if(isset($this->errors[$major_type][$val]))
					unset($this->errors[$major_type][$val]);
			}else{
				if(isset($this->errors[$val]))
					unset($this->errors[$val]);
			}
		}
		
		// Save if flag is set and there are changes
		if($save_flag)
			$this->save('errors');
	}
	
	/**
	 * Deletes all errors from the plugin's data
	 *
	 * @param bool $save_flag
	 *
	 * @return void
	 */
	public function error_delete_all($save_flag = false)
	{
		$this->errors = new \ArrayObject($this->def_errors);
		if($save_flag)
			$this->save('errors');
	}
	
	public function error_toggle($add_flag = true, $type, $save_flag = false, $major_type = null){
		if($add_flag)
			$this->error_add($type, $save_flag, $major_type);
		else
			$this->error_delete($type, $save_flag, $major_type);
	}
	
	public function __set($name, $value) 
    {
        $this->storage[$name] = $value;
    }

    public function __get($name) 
    {
        if (array_key_exists($name, $this->storage)){
            return $this->storage[$name];
        }else{
			$this->getOption($name);
			return $this->storage[$name];
		}
	
		// return !empty($this->storage[$name]) ? $this->storage[$name] : null;
    }
	
    public function __isset($name) 
    {
        return isset($this->storage[$name]);
    }
	
    public function __unset($name) 
    {
        unset($this->storage[$name]);
    }
	
	public function __call($name, $arguments)
	{
        error_log ("Calling method '$name' with arguments: " . implode(', ', $arguments). "\n");
    }
	
    public static function __callStatic($name, $arguments)
	{
        error_log("Calling static method '$name' with arguments: " . implode(', ', $arguments). "\n");
    }
	
	public function server(){
		return \CleantalkAP\Variables\Server::getInstance();
	}
	public function cookie(){
		return \CleantalkAP\Variables\Cookie::getInstance();
	}
	public function request(){
		return \CleantalkAP\Variables\Request::getInstance();
	}
	public function post(){
		return \CleantalkAP\Variables\Post::getInstance();
	}
	public function get(){
		return \CleantalkAP\Variables\Get::getInstance();
	}
}
