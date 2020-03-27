<?php

namespace CleantalkAP\Common;

/**
 * Class Cron
 *
 * Provide instrument for schelduled tasks
 *
 * Contains methods that should be reassigned
 *
 * @package \CleantalkAP\Common
 * @subpackage Cron
 * @Version 1.1
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

class Cron
{
	public $tasks = array(); // Array with tasks
	public $tasks_to_run = array(); // Array with tasks which should be run now
	public $tasks_completed = array(); // Result of executed tasks
	
	// Currently selected task
	public  $task;
	protected $handler;
	protected $period;
	protected $next_call;
	protected $params;
	protected $errors;
	
	/**
	 * Cron constructor.
	 */
	public function __construct()
	{
		$tasks = static::getTasks();
		$this->errors = static::getErrors();
		$this->tasks = empty($tasks) ? array() : $tasks;
	}
	
	static public function getErrors(){
		return Err::getInstance();
	}
	
	/**
	 * Return arrray with tasks
	 * Should be rewritten for specific platform
	 *
	 * @return array
	 */
	static public function getTasks(){
		return array();
	}
	
	/**
	 * Save tasks in some way
	 * Should be rewritten for specific platform
	 *
	 * @param $tasks
	 *
	 * @return bool
	 */
	static public function saveTasks( $tasks ){
		return true;
	}
	
	/**
	 * Creates new entry in task list
	 *
	 * @param string   $task
	 * @param callable $handler
	 * @param int      $period
	 * @param int|null $first_call
	 * @param array    $params
	 *
	 * @return bool
	 */
	static public function addTask($task, $handler, $period, $first_call = null, $params = array())
	{
		// First call time() + preiod
		$first_call = !$first_call ? time() + $period : $first_call;
		
		$tasks = static::getTasks();
		
		if(isset($tasks[$task]))
			return false;
		
		// Task entry
		$tasks[$task] = array(
			'handler' => $handler,
			'next_call' => $first_call,
			'period' => $period,
			'params' => $params,
		);
		
		return static::saveTasks( $tasks );
	}
	
	/**
	 * Remove task from the list and save it to base
	 *
	 * @param string $task
	 *
	 * @return bool
	 */
	static public function removeTask($task)
	{
		$tasks = static::getTasks();
		
		if(!isset($tasks[$task]))
			return false;
		
		unset($tasks[$task]);
		
		return static::saveTasks($tasks);
	}
	
	/**
	 * Updates cron task, create task if not exists
	 * Save it to base
	 *
	 * @param string   $task
	 * @param callable $handler
	 * @param int      $period
	 * @param int|null $first_call
	 * @param array    $params
	 *
	 * @return bool
	 */
	static public function updateTask($task, $handler, $period, $first_call = null, $params = array()){
		return static::removeTask($task) &&
		       static::addTask($task, $handler, $period, $first_call, $params);
	}
	
	/**
	 * Getting tasks which should be run.
	 * Putting tasks that should be run to $this->tasks_to_run
	 *
	 * @return array|bool
	 */
	public function checkTasks()
	{
		if(empty($this->tasks))
			return true;
		
		foreach($this->tasks as $task => $task_data){
			
			if($task_data['next_call'] <= time())
				$this->tasks_to_run[] = $task;
			
		}unset($task, $task_data);
		
		return $this->tasks_to_run;
	}
	
	/**
	 * Runs all tasks from $this->tasks_to_run
	 * Saves all results to (array) $this->tasks_completed
	 *
	 * @return void
	 */
	public function runTasks()
	{
		if(empty($this->tasks_to_run)){
			return;
		}
		
		foreach($this->tasks_to_run as $task){
			
			$this->selectTask($task);
			
			if(function_exists($this->handler)){
				
				$result = call_user_func_array($this->handler, isset($this->params) ? $this->params : array());
				
				if(empty($result['error'])){
					$this->tasks_completed[$task] = true;
					$this->errors::delete('cron', $task);
				}else{
					$this->tasks_completed[$task] = false;
					$this->errors::add('cron', $task, $result);
				}
				
			}else{
				$this->tasks_completed[$task] = false;
				$this->errors::add('cron', $task, 'function ' . $this->handler . ' is not exists.');
			}
			
			$this->saveSelectedTask($task);
			
		}unset($task);
		
		// Merging executed tasks with updated during execution
		$tasks = $this->getTasks();
		
		foreach($tasks as $task => $task_data){
			
			// Task where added during execution
			if(!isset($this->tasks[$task])){
				$this->tasks[$task] = $task_data;
				continue;
			}
			
			// Task where updated during execution
			if($task_data !== $this->tasks[$task]){
				$this->tasks[$task] = $task_data;
				continue;
			}
			
			// Setting next call depending on results
			if(isset($this->tasks[$task], $this->tasks_completed[$task])){
				$this->tasks[$task]['next_call'] = $this->tasks_completed[$task]
					? time() + $this->tasks[$task]['period']
					: time() + round($this->tasks[$task]['period']/4);
			}
			
			if(empty($this->tasks[$task]['next_call']) || $this->tasks[$task]['next_call'] < time()){
				$this->tasks[$task]['next_call'] = time() + $this->tasks[$task]['period'];
			}
			
		} unset($task, $task_data);
		
		// Task where deleted during execution
		$tmp = $this->tasks;
		foreach($tmp as $task => $task_data){
			if(!isset($tasks[$task]))
				unset($this->tasks[$task]);
		} unset($task, $task_data);
		
		//*/ End of merging
		
		static::saveTasks( $this->tasks );
		
		return;
	}
	
	/**
	 * Save a task to private properties for comfortable use
	 *
	 * @param string $task
	 */
	protected function selectTask($task)
	{
		$this->task      = $task;
		$this->handler   = $this->tasks[$task]['handler'];
		$this->period    = $this->tasks[$task]['period'];
		$this->next_call = $this->tasks[$task]['next_call'];
		$this->params    = isset($this->tasks[$task]['params']) ? $this->tasks[$task]['params'] : array();
	}
	
	/**
	 * Save task from private properties to public for comfortable use
	 *
	 * @param string $task
	 */
	protected function saveSelectedTask($task)
	{
		$task = $this->task;
		
		$this->tasks[$task]['handler']   = $this->handler;
		$this->tasks[$task]['period']    = $this->period;
		$this->tasks[$task]['next_call'] = $this->next_call;
		$this->tasks[$task]['params']    = $this->params;
	}
}
