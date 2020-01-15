<?php

namespace CleantalkAP\Variables;

/**
 * Class Cookie
 * Safety handler for $_COOKIE
 *
 * @usage \CleantalkAP\Variables\Cookie::get( $name );
 *
 * @package \CleantalkAP\Variables
 */
class Cookie extends SuperGlobalVariables{
	
	static $instance;
	
	/**
	 * Gets given $_COOKIE variable and seva it to memory
	 * @param $name
	 *
	 * @return mixed|string
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		if( function_exists( 'filter_input' ) )
			$value = filter_input( INPUT_COOKIE, $name );
		
		if( empty( $value ) )
			$value = isset( $_COOKIE[ $name ] ) ? $_COOKIE[ $name ]	: '';
			
		return $value;
	}
}