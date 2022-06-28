<?php

namespace Cleantalk\Common\Firewall;

/**
 * The abstract class for any FireWall modules.
 * Compatible with any CMS.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

use Cleantalk\Common\DB;
use Cleantalk\Common\Helper;
use Cleantalk\Common\Variables\Get;

abstract class FirewallModule {

    /**
     * @var string
     */
    protected $api_key;

    /**
     * @var string
     */
	public $module_name = 'FireWall Module';

    /**
     * @var array
     */
	protected $ip_array = array();

    /**
     * @var DB
     */
	protected $db;

    /**
     * @var string
     */
    protected $db_log_table_name;

    /**
     * @var string
     */
	protected $db_data_table_name;

    /**
     * @var Helper
     */
	protected $helper;

	/**
	 * @var string
	 */
	protected $real_ip;

	/**
	 * @var string
	 */
	protected $test_ip;

	/**
	 * @var bool
	 */
	protected $test;

    /**
     * @var bool
     */
    protected $debug;

    /**
     * @var array
     */
    protected $debug_data = array();

    /**
	 * FirewallModule constructor.
	 * Use this method to prepare any data for the module working.
	 *
	 * @param string $data_table
	 * @param array $params
	 */
	abstract public function __construct( $data_table, $params = array() );

    /**
     * Use this method to execute main logic of the module.
     *
     * @return array  Array of the check results
     */
    abstract public function check();

    /**
     * Do logic for denied request.
     *
     * @param string $result
     * @return void
     */
    abstract public function actionsForDenied( $result );

    /**
     * Do logic for allowed request.
     *
     * @param string $result
     * @return void
     */
    abstract public function actionsForPassed( $result );

    /**
     * Configure and set additional properties: real_ip, test_ip, test
     *
     * @param array $ips
     * @return void
     */
    public function ipAppendAdditional( $ips )
	{
		$this->real_ip = isset($ips['real']) ? $ips['real'] : null;

		if( Get::get('sfw_test_ip') && Helper::ip__validate( Get::get('sfw_test_ip') ) !== false ) {
            $this->ip_array['sfw_test'] = Get::get( 'sfw_test_ip' );
            $this->test_ip   = Get::get( 'sfw_test_ip' );
            $this->test      = true;
        }
	}
	
	/**
     * Set specify CMS based DB instance
     *
	 * @param DB $db
	 */
	public function setDb( DB $db )
    {
		$this->db = $db;
	}

    /**
     * Set Log Table name
     *
     * @param string $log_table_name
     */
    public function setLogTableName( $log_table_name )
    {
        $this->db_data_table_name = $this->db->prefix . $this->db_data_table_name;
        $this->db_log_table_name = $log_table_name;
    }

    /**
     * Set specify CMS based Helper instance
     *
     * @param Helper $helper
     */
    public function setHelper( Helper $helper )
    {
        $this->helper = $helper;
    }

    /**
     * Set API KEY
     *
     * @param string $api_key
     */
    public function setApiKey( $api_key )
    {
        $this->api_key = $api_key;
    }

    /**
     * Set is debug property.
     *
     * @param bool $debug
     */
    public function setIsDebug( $debug )
    {
        $this->debug = $debug;
    }

	/**
     * Set visitor's IP
     *
	 * @param array $ip_array    $ip_array = array( 'real' => '1.2.3.4' )
	 */
	public function setIpArray( $ip_array )
    {
		$this->ip_array = $ip_array;
	}

    /**
     * Default die page for blocked requests.
     *
     * @param array $result
     */
    public function _die( $result )
    {
		// Headers
		if( headers_sent() === false ){
			header('Expires: '.date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
			header('Cache-Control: no-store, no-cache, must-revalidate');
			header('Cache-Control: post-check=0, pre-check=0', FALSE);
			header('Pragma: no-cache');
			header("HTTP/1.0 403 Forbidden");
		}
	}

    /**
     * This is a placeholder for WP translation function.
     * For compatibility with any CMS.
     *
     * @param $string
     * @param $text_domain
     * @return mixed
     */
    public function __( $string, $text_domain )
    {
//        if( function_exists( '__' ) ) {
//            return __( $string, $text_domain );
//        }
        return $string;
    }

}