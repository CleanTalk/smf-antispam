<?php

namespace CleantalkAP\Variables;

/**
 * Class Get
 * Safety handler for $_GET
 *
 * @usage \CleantalkAP\Variables\Get::get( $name );
 *
 * @package \CleantalkAP\Variables
 */
class Get extends SuperGlobalVariables{
	
	static $instance;
	
	/**
	 * Gets given $_GET variable and seva it to memory
	 * @param $name
	 *
	 * @return mixed|string
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variable[$name];
		
		if( function_exists( 'filter_input' ) )
			$value = filter_input( INPUT_GET, $name );
		
		if( empty( $value ) )
			$value = isset( $_GET[ $name ] ) ? $_GET[ $name ]	: '';
		
		// Remember for thurther calls
		static::getInstance()->remember_variable( $name, $value );
		
		return $value;
	}
}