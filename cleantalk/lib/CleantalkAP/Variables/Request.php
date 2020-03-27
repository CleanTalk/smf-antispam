<?php

namespace CleantalkAP\Variables;

/**
 * Class Request
 * Safety handler for $_REQUEST
 *
 * @usage \CleantalkAP\Variables\Request::get( $name );
 *
 * @package \CleantalkAP\Variables
 */
class Request extends SuperGlobalVariables{
	
	static $instance;
	
	/**
	 * Gets given $_REQUEST variable and seva it to memory
	 * @param $name
	 *
	 * @return mixed|string
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		$value = isset( $_REQUEST[ $name ] ) ? $_REQUEST[ $name ]	: '';
		
		// Remember for thurther calls
		static::getInstance()->remember_variable( $name, $value );
		
		return $value;
	}
}