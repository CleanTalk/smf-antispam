<?php

/**
Cleantalk Spam FireWall class
**/

class CleanTalkSFW
{
	public $ip_array = Array();
	public $blocked_ip = '';
	public $result = false;
	
	public function cleantalk_get_real_ip()
	{
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
			$the_ip = trim($the_ip[0]);
			$this->ip_array[]=$the_ip;
		}
		if ( array_key_exists( 'HTTP_X_FORWARDED_FOR', $headers ))
		{
			$the_ip=explode(",", trim($headers['HTTP_X_FORWARDED_FOR']));
			$the_ip = trim($the_ip[0]);
			$this->ip_array[]=$the_ip;
		}
		$the_ip = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		$this->ip_array[]=$the_ip;

		if(isset($_GET['sfw_test_ip']))
		{
			$the_ip=$_GET['sfw_test_ip'];
			$this->ip_array[]=$the_ip;
		}
		$this->ip_array = array_unique($this->ip_array);
		sort($this->ip_array);
	}
	
	public function check_ip()
	{
		$passed_ip='';
		global $smcFunc, $db_connection;
		if (!isset($db_connection) || $db_connection === false) {
		    loadDatabase();
		}
                $table_exists = false;
		if (isset($db_connection) && $db_connection != false) {
			$sql="SHOW TABLES LIKE '{db_prefix}cleantalk_sfw'";
			$result = $smcFunc['db_query']('', $sql, Array());
                        $row = $smcFunc['db_fetch_assoc'] ($result);
                        if (isset($row) && is_array($row)) {
                            $table_exists = true;
                        }
		}

		for($i=0;$i<sizeof($this->ip_array);$i++)
		{
		    if (isset($db_connection) && $db_connection != false && $table_exists === true) {
			$sql='SELECT count(network) as cnt FROM {db_prefix}cleantalk_sfw WHERE network = '.sprintf("%u", ip2long($this->ip_array[$i])).' & mask';
			$result = $smcFunc['db_query']('', $sql, Array());
			$row = $smcFunc['db_fetch_assoc'] ($result);
    			$cnt = intval($row['cnt']);

			if($cnt>0)
			{
				$this->result=true;
				$this->blocked_ip=$this->ip_array[$i];
			}
			else
			{
				$passed_ip = $this->ip_array[$i];
			}
		    }
		    else
		    {
			$passed_ip = $this->ip_array[$i];
		    }
		}
		if($passed_ip!='')
		{
			$key=cleantalk_get_api_key();
                        @setcookie ('ct_sfw_pass_key', md5($passed_ip.$key), 0, "/");
		}
	}
	
	public function sfw_die()
	{
		$key=cleantalk_get_api_key();
		$sfw_die_page=file_get_contents(dirname(__FILE__)."/sfw_die_page.html");
		$sfw_die_page=str_replace("{REMOTE_ADDRESS}",$this->blocked_ip,$sfw_die_page);
		$sfw_die_page=str_replace("{REQUEST_URI}",$_SERVER['REQUEST_URI'],$sfw_die_page);
		$sfw_die_page=str_replace("{SFW_COOKIE}",md5($this->blocked_ip.$key),$sfw_die_page);
		@header('HTTP/1.0 403 Forbidden');
		echo $sfw_die_page;
		die();
	}
}

?>
