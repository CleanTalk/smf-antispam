<?php

namespace CleantalkAP\SMF;

/**
 * Class Err
 * Uses singleton template.
 * Errors handling
 *
 * @package Cleantalk
 */
class Err extends \CleantalkAP\Common\Err
{
	
	static $instance;
	
	/**
	 * @var \SpbcState
	 */
	private $spbc;
	
	/**
	 * Alternative constructor
	 */
	protected function init(){
		global $spbc;
		$this->spbc = $spbc;
		// $this->load();
	}
	
	/**
	 * Loads saved errors from DB
	 */
	public function load(){
		$errors = get_option('spbc_errors');
		$this->errors = $errors ? $errors : array();
	}
	
	/**
	 * Save loaded errors to DB
	 */
	public function save(){
		update_option('spbct_errors', $this->errors);
	}
	
	/**
	 * Adds new error
	 */
	public static function add(){
		$args = func_get_args();
		if(count($args) === 3){
			static::getInstance()->spbc->error_add(
				$args[2],
				$args[1],
				$args[0]
			);
		}else{
			static::getInstance()->spbc->error_add(
				$args[0],
				$args[1],
			);
		}
	}
	
	/**
	 * Adds new error
	 */
	public static function delete(){
		$args = func_get_args();
		if(count($args) === 2){
			static::getInstance()->spbc->error_delete(
				$args[1],
				true,
				$args[0],
			);
		}else{
			static::getInstance()->spbc->error_delete(
				$args[0],
				true
			);
		}
	}
}