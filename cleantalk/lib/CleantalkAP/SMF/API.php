<?php

namespace CleantalkAP\SMF;

/**
 * CleanTalk API class.
 * Mostly contains wrappers for API methods. Check and send mehods.
 * Compatible with any CMS.
 *
 * @version       3.2
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class API extends \CleantalkAP\Common\API{
	
	static public function get_agent(){
		return defined( 'SPBC_AGENT' ) ? SPBC_AGENT : static::DEFAULT_AGENT;
	}
	
	/**
	 * Function sends raw request to API server
	 *
	 * @param array   $data    to send
	 * @param string  $url     of API server
	 * @param boolean $ssl     use ssl on not
	 *
	 * @return array|bool
	 */
	static public function send_request($data, $url = self::URL, $ssl = false)
	{
		global $spbc;
		
		// Possibility to switch API url
		$url = defined('SPBC_API_URL') ? SPBC_API_URL : $url;
		
		// Adding agent version to data
		$data['agent'] = static::get_agent();
		
		// Use Wordpress builtin HTTP API
		if($spbc->settings['use_buitin_http_api']){
			
			$args = array(
				'body' => $data,
				'timeout' => 5,
				'user-agent' => SPBC_AGENT.' '.get_bloginfo( 'url' ),
			);
			
			$result = wp_remote_post($url, $args);
			
			if( is_wp_error( $result ) ) {
				$errors = $result->get_error_message();
				$result = false;
			}else{
				$result = wp_remote_retrieve_body($result);
			}
			
		// Use Cleantalk CURL version if disabled
		}else{
			// Default preset is 'api'
			$presets = array( 'api' );
			
			// Add ssl to 'presets' if enabled
			if( $ssl )
				array_push( $presets, 'ssl' );
			
			$result = \CleantalkAP\SMF\Helper::http__request( $url, $data,  $presets );
			
			// Retry with SSL enabled if failed
			if( ! empty ( $result['error'] ) && $ssl === false )
				$result = \CleantalkAP\SMF\Helper::http__request( $url, $data, 'api ssl' );
		}
		
		return empty($result) || !empty($errors)
			? array('error' => $errors)
			: $result;
		
	}
}