<?php

namespace Cleantalk\Common\Firewall\Modules;

use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Firewall\FirewallModule;
use Cleantalk\Common\Schema;
use Cleantalk\Common\Variables\Cookie;
use Cleantalk\Common\Variables\Get;
use Cleantalk\Common\Variables\Server;

class SFW extends FirewallModule {

    public $module_name = 'SFW';

	// Additional params
	private $sfw_counter = false;
	private $set_cookies = false;
	private $cookie_domain = false;

    /**
     * FireWall_module constructor.
     * Use this method to prepare any data for the module working.
     *
     * @param string $data_table
     * @param array $params
     */
	public function __construct( $data_table, $params = array() )
    {
		$this->db_data_table_name = $data_table ?: null;
		
		foreach( $params as $param_name => $param ){
			$this->$param_name = isset( $this->$param_name ) ? $param : false;
		}
	}
	
	/**
	 * Use this method to execute main logic of the module.
	 *
	 * @return array  Array of the check results
	 */
	public function check()
    {
		$results = array();
        $status = 0;
		
		// Skip by cookie
		foreach( $this->ip_array as $current_ip ){

			if( substr( Cookie::get( 'ct_sfw_pass_key' ), 0, 32 ) == md5( $current_ip . $this->api_key ) ){

                if( Cookie::get( 'ct_sfw_passed' ) ){

                    if( ! headers_sent() ){
                        \Cleantalk\Common\Helper::apbct_cookie__set( 'ct_sfw_passed', '0', time() + 86400 * 3, '/', null, false, true, 'Lax' );
                    } else {
                        $results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_SFW__BY_COOKIE', );
                    }

                    // Do logging an one passed request
                    $this->update_log( $current_ip, 'PASS_SFW' );

                    if( $this->sfw_counter ){
                        // @ToDo have to implement the logic of incrementing and saving count of all handled requests.
                    }

                }

                if( strlen( Cookie::get( 'ct_sfw_pass_key' ) ) > 32 ) {
                    $status = substr( Cookie::get( 'ct_sfw_pass_key' ), -1 );
                }

                if( $status ) {
                    $results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_SFW__BY_WHITELIST',);
                }
					
				return $results;
			}
		}
		
		// Common check
		foreach( $this->ip_array as $origin => $current_ip )
		{
			$current_ip_v4 = sprintf("%u", ip2long($current_ip));
			for ( $needles = array(), $m = 6; $m <= 32; $m ++ ) {
				$mask      = str_repeat( '1', $m );
				$mask      = str_pad( $mask, 32, '0' );
				$needles[] = sprintf( "%u", bindec( $mask & base_convert( $current_ip_v4, 10, 2 ) ) );
			}
			$needles = array_unique( $needles );
			
			$db_results = $this->db->fetch_all("SELECT
				network, mask, status
				FROM " . $this->db_data_table_name . "
				WHERE network IN (". implode( ',', $needles ) .")
				AND	network = " . $current_ip_v4 . " & mask 
				AND " . rand( 1, 100000 ) . "  
				ORDER BY status DESC");
			
			if( ! empty( $db_results ) ){
				
				foreach( $db_results as $db_result ){
					
					if( $db_result['status'] == 1 ) {
                        $results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_SFW__BY_WHITELIST',);
                        break;
                    }
					else
						$results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'DENY_SFW',);
					
				}
				
			}else{
				
				$results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_SFW' );
				
			}
		}
		
		return $results;
	}
	
	/**
	 * Add entry to SFW log.
	 * Writes to database.
	 *
	 * @param string $ip
	 * @param string $status
	 */
	public function update_log( $ip, $status )
    {

		$id   = md5( $ip . $this->module_name );
		$time = time();
		
		$query = "INSERT INTO " . $this->db_log_table_name . "
		SET
			id = '$id',
			ip = '$ip',
			status = '$status',
			all_entries = 1,
			blocked_entries = " . ( strpos( $status, 'DENY' ) !== false ? 1 : 0 ) . ",
			entries_timestamp = '" . $time . "',
			ua_name = '" . Server::get('HTTP_USER_AGENT') . "'
		ON DUPLICATE KEY
		UPDATE
			status = '$status',
			all_entries = all_entries + 1,
			blocked_entries = blocked_entries" . ( strpos( $status, 'DENY' ) !== false ? ' + 1' : '' ) . ",
			entries_timestamp = '" . intval( $time ) . "',
			ua_name = '" . Server::get('HTTP_USER_AGENT') . "'";
		
		$this->db->execute( $query );
	}

    /**
     * @inheritdoc
     */
    public function actionsForDenied( $result )
    {
		if( $this->sfw_counter ){
            // @ToDo have to implement the logic of incrementing and saving count of blocked requests.
		}
	}

    /**
     * @inheritdoc
     */
	public function actionsForPassed( $result )
    {
		if( $this->set_cookies &&  ! headers_sent() ) {
		    $status = $result['status'] === 'PASS_SFW__BY_WHITELIST' ? '1' : '0';
            $cookie_val = md5( $result['ip'] . $this->api_key ) . $status;
            $helper = $this->helper;
            $helper::apbct_cookie__set( 'ct_sfw_pass_key', $cookie_val, time() + 86400 * 30, '/', null, false );
        }
	}

    /**
     * @inheritdoc
     */
	public function _die( $result )
    {
		
		parent::_die( $result );
		
		// Statistics
		if( ! empty( $this->blocked_ips ) ){
			reset($this->blocked_ips);
            // @ToDo have to implement the logic of saving last_sfw_block info.
			/*
			$this->apbct->stats['last_sfw_block']['time'] = time();
			$this->apbct->stats['last_sfw_block']['ip'] = $result['ip'];
			$this->apbct->save('stats');
			*/
		}
		
		// File exists?
		if( file_exists( __DIR__ . "/lib/Cleantalk/ApbctWP/Firewall/die_page_sfw.html" ) ){
			
			$sfw_die_page = file_get_contents( __DIR__ . "/lib/Cleantalk/ApbctWP/Firewall/die_page_sfw.html" );

            $net_count = $this->db->fetch( 'SELECT COUNT(*) as net_count FROM ' . $this->db_data_table_name )['net_count'];

            $status = $result['status'] === 'PASS_SFW__BY_WHITELIST' ? '1' : '0';
            $cookie_val = md5( $result['ip'] . $this->api_key ) . $status;

			// Translation
			$replaces = array(
				'{SFW_DIE_NOTICE_IP}'              => $this->__('SpamFireWall is activated for your IP ', 'cleantalk-spam-protect'),
				'{SFW_DIE_MAKE_SURE_JS_ENABLED}'   => $this->__( 'To continue working with the web site, please make sure that you have enabled JavaScript.', 'cleantalk-spam-protect' ),
				'{SFW_DIE_CLICK_TO_PASS}'          => $this->__('Please click the link below to pass the protection,', 'cleantalk-spam-protect'),
				'{SFW_DIE_YOU_WILL_BE_REDIRECTED}' => sprintf( $this->__('Or you will be automatically redirected to the requested page after %d seconds.', 'cleantalk-spam-protect'), 3),
				'{CLEANTALK_TITLE}'                => ($this->test ? $this->__('This is the testing page for SpamFireWall', 'cleantalk-spam-protect') : ''),
				'{REMOTE_ADDRESS}'                 => $result['ip'],
				'{SERVICE_ID}'                     => $net_count,
				'{HOST}'                           => '',
				'{GENERATED}'                      => '<p>The page was generated at&nbsp;' . date( 'D, d M Y H:i:s' ) . "</p>",
				'{REQUEST_URI}'                    => Server::get( 'REQUEST_URI' ),
				
				// Cookie
				'{COOKIE_PREFIX}'      => '',
				'{COOKIE_DOMAIN}'      => $this->cookie_domain,
				'{COOKIE_SFW}'         => $this->test ? $this->test_ip : $cookie_val,
				
				// Test
				'{TEST_TITLE}'      => '',
				'{REAL_IP__HEADER}' => '',
				'{TEST_IP__HEADER}' => '',
				'{TEST_IP}'         => '',
				'{REAL_IP}'         => '',
			);
			
			// Test
			if($this->test){
				$replaces['{TEST_TITLE}']      = $this->__( 'This is the testing page for SpamFireWall', 'cleantalk-spam-protect' );
				$replaces['{REAL_IP__HEADER}'] = 'Real IP:';
				$replaces['{TEST_IP__HEADER}'] = 'Test IP:';
				$replaces['{TEST_IP}']         = $this->test_ip;
				$replaces['{REAL_IP}']         = $this->real_ip;
			}
			
			// Debug
			if($this->debug){
				$debug = '<h1>Headers</h1>'
				         . var_export( apache_request_headers(), true )
				         . '<h1>REMOTE_ADDR</h1>'
				         . Server::get( 'REMOTE_ADDR' )
				         . '<h1>SERVER_ADDR</h1>'
				         . Server::get( 'REMOTE_ADDR' )
				         . '<h1>IP_ARRAY</h1>'
				         . var_export( $this->ip_array, true )
				         . '<h1>ADDITIONAL</h1>'
				         . var_export( $this->debug_data, true );
			}
			$replaces['{DEBUG}'] = isset( $debug ) ? $debug : '';
			
			foreach( $replaces as $place_holder => $replace ){
				$sfw_die_page = str_replace( $place_holder, $replace, $sfw_die_page );
			}
			
			die( $sfw_die_page );
			
		}

        die( "IP BLACKLISTED. Blocked by SFW " . $result['ip'] );

    }

}