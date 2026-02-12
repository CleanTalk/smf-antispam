<?php

namespace Cleantalk\Common;

use Cleantalk\Common\Variables\Get;
use Cleantalk\Common\Helper;

abstract class RemoteCalls
{

    const COOLDOWN = 10;

    /**
     * @var bool
     */
    private $rc_running;

    /**
     * @var string
     */
    protected $api_key;

    protected $default_rc = [
        'close_renew_banner' => [
            'last_call' => 0,
            'cooldown' => self::COOLDOWN,
        ],
        'sfw_update' => [
            'last_call' => 0,
            'cooldown' => self::COOLDOWN,
        ],
        'sfw_send_logs' => [
            'last_call' => 0,
            'cooldown' => self::COOLDOWN,
        ],
        'sfw_update__write_base' => [
            'last_call' => 0,
            'cooldown' => 0,
        ],
    ];

    /**
     * @var array
     */
    private $available_rc_actions;

    public function __construct( $api_key )
    {
        $this->api_key = $api_key;
        $this->available_rc_actions = $this->getAvailableRcActions();
    }

    /**
	 * Checking if the current request is the Remote Call
	 *
	 * @return bool
	 */
	public static function check()
    {
		return
			Get::get( 'spbc_remote_call_token' )
			? self::checkWithToken()
            : self::checkWithoutToken();
	}

    public static function checkWithToken()
    {
        return Get::get('spbc_remote_call_token') &&
               Get::get('spbc_remote_call_action') &&
               in_array(Get::get('plugin_name'), array('antispam', 'anti-spam', 'apbct'));
    }

    public static function checkWithoutToken()
    {
        global $apbct;

        $rc_servers = [
            'netserv3.cleantalk.org',
            'netserv4.cleantalk.org',
        ];
        // Resolve IP of the client making the request and verify hostname from it to be in the list of RC servers hostnames
        $client_ip = Helper::ip__get('remote_addr');
        $verified_hostname = $client_ip ? Helper::ip__resolve($client_ip) : false;
        $is_noc_request = ! $apbct->key_is_ok &&
            Get::get('spbc_remote_call_action') &&
            in_array(Get::get('plugin_name'), array('antispam', 'anti-spam', 'apbct')) &&
            $verified_hostname !== false &&
            in_array($verified_hostname, $rc_servers, true);

        // no token needs for this action, at least for now

        $is_wp_nonce_request = $apbct->key_is_ok && Get::get('spbc_remote_call_action') === 'get_fresh_wpnonce';

        return $is_wp_nonce_request || $is_noc_request;
    }

    /**
     * Execute corresponding method of RemoteCalls if exists
     *
     * @return void|string
     */
    public function perform()
    {
        $action = strtolower( Get::get( 'spbc_remote_call_action' ) );
        $token  = strtolower( Get::get( 'spbc_remote_call_token' ) );

        $actions = $this->available_rc_actions;

        if( count( $actions ) !== 0 && array_key_exists( $action, $actions ) ){

            $cooldown = isset( $actions[$action]['cooldown'] ) ? $actions[$action]['cooldown'] : self::COOLDOWN;

            // Return OK for test remote calls
            if ( Get::get( 'test' ) ) {
                die('OK');
            }

            if( time() - $actions[ $action ]['last_call'] >= $cooldown ){

                $actions[$action]['last_call'] = time();

                $this->setLastCall( $action );

                // Check API key
                if( $token === strtolower( md5( $this->api_key ) ) ){

                    // Flag to let plugin know that Remote Call is running.
                    $this->rc_running = true;

                    $action_method = 'action__' . $action;

                    if( method_exists( static::class, $action_method ) ){

                        // Delay before perform action;
                        if ( Get::get( 'delay' ) ) {
                            sleep(Get::get('delay'));
                        }

                        $action_result = static::$action_method();

                        $response = empty( $action_result['error'] )
                            ? 'OK'
                            : 'FAIL ' . json_encode( array( 'error' => $action_result['error'] ) );

                        if( ! Get::get( 'continue_execution' ) ){

                            die( $response );

                        }

                        return $response;

                    }else
                        $out = 'FAIL '.json_encode(array('error' => 'UNKNOWN_ACTION_METHOD'));
                }else
                    $out = 'FAIL '.json_encode(array('error' => 'WRONG_TOKEN'));
            }else
                $out = 'FAIL '.json_encode(array('error' => 'TOO_MANY_ATTEMPTS'));
        }else
            $out = 'FAIL '.json_encode(array('error' => 'UNKNOWN_ACTION'));

        die( $out );
    }

    /**
     * Get available remote calls from the storage.
     *
     * @return array
     */
    abstract protected function getAvailableRcActions();

    /**
     * Set last call timestamp and save it to the storage.
     *
     * @param string $action
     * @return bool
     */
    abstract protected function setLastCall( $action );

}
