<?php

namespace CleantalkAP\SMF;

use \CleantalkAP\Variables\Server;

/**
 * CleanTalk Helper class.
 * Compatible with any CMS.
 *
 * @package       PHP Antispam by CleanTalk
 * @subpackage    Helper
 * @Version       3.2
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class Helper extends \CleantalkAP\Common\Helper{
	
	static public function http__user_agent(){
		return defined( 'SPBC_USER_AGENT' ) ? SPBC_USER_AGENT : static::DEFAULT_USER_AGENT;
	}
	
	/**
	 * Wrapper for http_request
	 * Requesting HTTP response code for $url
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	static public function http__request__get_response_code( $url ){
		return self::http__request( $url, array(), 'get_code');
	}
	
	/**
	 * Wrapper for http_request
	 * Requesting data via HTTP request with GET method
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	static public function http__request__get_content( $url ){
		return self::http__request( $url, array(), 'get');
	}
	
	/**
	 * Escapes MySQL params
	 *
	 * @param string|int $param
	 * @param string     $quotes
	 *
	 * @return int|string
	 */
	public static function db__prepare_param($param, $quotes = '\'')
	{
		if(is_array($param)){
			foreach($param as &$par){
				$par = self::db__prepare_param($par);
			}
		}
		switch(true){
			case is_numeric($param):
				$param = intval($param);
				break;
			case is_string($param) && strtolower($param) == 'null':
				$param = 'NULL';
				break;
			case is_string($param):
				global $wpdb;
				$param = $quotes . $wpdb->_real_escape($param) . $quotes;
				break;
		}
		return $param;
	}
	
	public static function time__get_interval_start( $interval = 300 ){
		return time() - ( ( time() - strtotime( date( 'd F Y' ) ) ) % $interval );
	}
}