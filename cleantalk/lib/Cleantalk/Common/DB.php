<?php

namespace Cleantalk\Common;

/**
 * CleanTalk abstract Data Base driver.
 * Shows what should be inside.
 * Uses singleton pattern.
 *
 * @version 1.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam
 */

abstract class DB
{

    private static $instance;

    /**
     * @var array Processed result
     */
    public $result = array();

    /**
     * @var string Database prefix
     */
    public $prefix = '';

    public function __construct() {	}
    public function __clone() { }
    public function __wakeup() 	{ }

    public static function getInstance()
    {
        if ( ! isset( self::$instance ) ) {
            self::$instance = new static();
            self::$instance->init();
        }
        return self::$instance;
    }

    /**
     * Alternative constructor.
     * Initilize Database object and write it to property.
     * Set tables prefix.
     */
    abstract protected function init();

    /**
     * Set $this->query string for next uses
     *
     * @param $query
     * @return $this
     */
    abstract public function set_query( $query );

    /**
     * Safely replace place holders
     *
     * @param string $query
     * @param array  $vars
     *
     * @return $this
     */
    abstract public function prepare( $query, $vars = array() );

    /**
     * Run any raw request
     *
     * @param $query
	 * @param $data
     *
     * @return bool|int Raw result
     */
    abstract public function execute( $query, $data = array() );

    /**
     * Fetchs first column from query.
     * May receive raw or prepared query.
     *
     * @param bool $query
     * @param bool $response_type
     *
     * @return array|object|void|null
     */
    abstract public function fetch( $query = false, $response_type = false );

    /**
     * Fetchs all result from query.
     * May receive raw or prepared query.
     *
     * @param bool $query
     * @param bool $response_type
     *
     * @return array|object|null
     */
    abstract public function fetch_all( $query = false, $response_type = false );

    abstract public function get_last_error();

}