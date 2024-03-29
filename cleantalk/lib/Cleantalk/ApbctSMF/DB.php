<?php

namespace Cleantalk\ApbctSMF;

class DB extends \Cleantalk\Common\DB {
    /**
     * Alternative constructor.
     * Initilize Database object and write it to property.
     * Set tables prefix.
     */
    protected function init() {
        global $db_connection, $db_prefix;

        if (!isset($db_connection) || $db_connection === false){
            \loadDatabase();
        }
        $this->prefix = $db_prefix;
    }

    /**
     * Set $this->query string for next uses
     *
     * @param $query
     * @return $this
     */
    public function set_query( $query ) {
        $this->query = $query;
        return $this;
    }

    /**
     * Safely replace place holders
     *
     * @param string $query
     * @param array  $vars
     *
     * @return $this
     */
    public function prepare( $query, $vars = array() ) {

    }

    /**
     * Run any raw request
     *
     * @param $query
     *
     * @return bool|int Raw result
     */
    public function execute( $query, $data = array() ) {
        global $smcFunc;

        $data = array_merge($data, array('db_error_skip' => true));

        $this->result = $smcFunc['db_query'](
        	'',
			$query,
			$data
		);

        return $this->result;
    }

    /**
     * Fetchs first column from query.
     * May receive raw or prepared query.
     *
     * @param bool $query
     * @param bool $response_type
     *
     * @return array|object|void|null
     */
    public function fetch( $query = false, $response_type = false ) {
        global $smcFunc;
        
        $db_result = $smcFunc['db_query']('', $query, array('db_error_skip' => true));
        $this->result = $smcFunc['db_fetch_assoc']($db_result);
        $smcFunc['db_free_result']($db_result);

        return $this->result;
    }

    /**
     * Fetchs all result from query.
     * May receive raw or prepared query.
     *
     * @param bool $query
     * @param bool $response_type
     *
     * @return array|object|null
     */
    public function fetch_all( $query = false, $response_type = false ) {
        global $smcFunc;

        $db_result = $smcFunc['db_query']('', $query, array('db_error_skip' => true));
        $result = array();
        while ($row = $smcFunc['db_fetch_assoc']($db_result)){
            $result[] = $row;
        }
        $smcFunc['db_free_result']($db_result);
        $this->result = $result;
        return $this->result;
    }

    public function get_last_error() {

    }
}