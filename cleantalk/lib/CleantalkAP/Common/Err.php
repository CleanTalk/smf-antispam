<?php

namespace CleantalkAP\Common;

/**
 * Class Err
 * Uses singleton template.
 * Errors handling
 *
 * @package Cleantalk
 */
class Err{
	
	use \CleantalkAP\Templates\Singleton;
	
	static $instance;
	public $errors = [];
	
	/**
	 * Adds new error
	 *
	 */
	public static function add(){
		static::getInstance()->errors[] = implode(': ', func_get_args());
		return static::$instance;
	}
	
	public function prepend( $string ){
		$this->errors[ count( $this->errors ) - 1 ] = $string . ': ' . end( static::getInstance()->errors );
	}
	
	public function append( $string ){
		$this->string = $string . ': ' . $this->string;
	}
	
	public static  function get_last( $output_style = 'bool' ){
		$out = $out = (bool) static::$instance->errors;
		if($output_style == 'as_json')
			$out = json_encode( array('error' => end( static::$instance->errors ) ), true );
		if($output_style == 'string')
			$out = array('error' => end( static::$instance->errors ) );
		return $out;
	}
	
	public function get_all( $output_style = 'string' ){
		$out = static::$instance->errors;
		if($output_style == 'as_json')
			$out = json_encode( static::$instance->errors, true );
		return $out;
	}
	
	public static function check(){
		return (bool)static::$instance->errors;
	}
	
	public static function check_and_output( $output_style = 'string' ){
		if(static::check())
			return static::$instance->get_last( $output_style );
		else
			return false;
	}
}