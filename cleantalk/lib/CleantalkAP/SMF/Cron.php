<?php

namespace CleantalkAP\SMF;

use CleantalkAP\SMF\Err as Err;

/**
 * CleanTalk Security Cron class for Wordpress plugin Security by Cleantalk
 * 
 * @package Security Plugin by CleanTalk
 * @subpackage Cron
 * @Version 1.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

class Cron extends \CleantalkAP\Common\Cron
{
	/**
	 * Option name with cron data
	 */
	const CRON_OPTION_NAME = 'spbc_cron';
	
	/**
	 * Gets error object
	 *
	 * @return mixed|\CleantalkAP\Common\Err|Err
	 */
	static public function getErrors(){
		return Err::getInstance();
	}
	
	/**
	 * Return arrray with tasks
	 * Gets unserialized spbc_cron option from wp_option table
	 *
	 * @return array
	 */
	static public function getTasks(){
		$tasks = get_option(self::CRON_OPTION_NAME);
		return empty($tasks) ? array() : $tasks;
	}
	
	/**
	 * Save tasks to spbc_cron option in wp_option table
	 *
	 * @param $tasks
	 *
	 * @return bool
	 */
	static function saveTasks( $tasks )	{
		return update_option(self::CRON_OPTION_NAME, $tasks);
	}
}
