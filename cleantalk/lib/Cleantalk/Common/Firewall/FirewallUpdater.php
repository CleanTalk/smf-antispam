<?php

namespace Cleantalk\Common\Firewall;

use Cleantalk\Common\API;
use Cleantalk\Common\DB;
use Cleantalk\Common\Helper;
use Cleantalk\Common\RemoteCalls;
use Cleantalk\Common\Schema;
use Cleantalk\Common\Variables\Get;
use Cleantalk\Common\Variables\Server;

class FirewallUpdater
{
    /**
     * @var int
     */
    const WRITE_LIMIT = 5000;

    /**
     * @var string
     */
    private $api_key;

    /**
     * @var Helper
     */
    private $helper;

    /**
     * @var API
     */
    private $api;

    /**
     * @var DB
     */
    private $db;

    /**
     * @var string
     */
    private $fw_data_table_name;


    /**
     * FirewallUpdater constructor.
     *
     * @param string $api_key
     * @param DB $db
     * @param string $fw_data_table_name
     */
    public function __construct( $api_key, DB $db, $fw_data_table_name )
    {
        $this->api_key            = $api_key;
        $this->db                 = $db;
        $this->fw_data_table_name = $db->prefix . $fw_data_table_name;
        $this->helper             = new Helper();
        $this->api                = new API();
    }

    /**
     * Set specify CMS based Helper instance
     *
     * @param Helper $helper
     */
    public function setSpecificHelper( Helper $helper )
    {
        $this->helper = $helper;
    }

    /**
     * Set specify CMS based API instance
     *
     * @param API $api
     */
    public function setSpecificApi( API $api )
    {
        $this->api = $api;
    }


    public function update()
    {
        $helper = $this->helper;
        $fw_stats = $helper::getFwStats();

        // Prevent start another update at a time
        if( Get::get('spbc_remote_call_action') == 'sfw_update__write_base' &&
            ! Get::get('firewall_updating_id') &&
            $fw_stats['firewall_updating_id'] &&
            time() - $fw_stats['firewall_updating_last_start'] < 60 ){
            return true;
        }

        // Check if the update performs right now. Blocks remote calls with different ID
        if( Get::get('spbc_remote_call_action') == 'sfw_update__write_base' &&
            Get::get('firewall_updating_id') &&
            Get::get('firewall_updating_id') !== $fw_stats['firewall_updating_id']
        ) {
            return array( 'error' => 'FIREWALL_IS_UPDATING' );
        }

        // No updating without api key
        if( empty( $this->api_key ) ){
            return true;
        }

        // Set new update ID
        if( ! $fw_stats['firewall_updating_id'] || time() - $fw_stats['firewall_updating_last_start'] > 300 ){
            $helper::setFwStats(
                array(
                    'firewall_updating_id' => md5( rand( 0, 100000 ) ),
                    'firewall_updating_last_start' => time(),
                )
            );
        }

        if( RemoteCalls::check() ) {
            // Remote call is in process, do updating

            $file_urls   = Get::get('file_urls');
            $url_count   = Get::get('url_count');
            $current_url = Get::get('current_url');

            // Getting blacklists file here.
            if( ! $file_urls ){

                // @todo We have to handle errors here
                $this->createTempTables();
                $blacklists = $this->getSfwBlacklists( $this->api_key );

                if( empty( $blacklists['error'] ) ){
                    if( ! empty( $blacklists['file_url'] ) ){
                        $data = $this->unpackData( $blacklists['file_url'] );
                        if( empty( $data['error'] ) ) {
                            return Helper::http__request__rc_to_host(
                                'sfw_update__write_base',
                                array(
                                    'spbc_remote_call_token'  => md5( $this->api_key ),
                                    'firewall_updating_id'    => $fw_stats['firewall_updating_id'],
                                    'file_urls'               => str_replace( array( 'http://', 'https://' ), '', $blacklists['file_url'] ),
                                    'url_count'               => count( $data ),
                                    'current_url'             => 0,
                                ),
                                array( 'get','async' )
                            );
                        } else {
                            return $data;
                        }
                    } else {
                        return array('error' => 'NO_REMOTE_MULTIFILE_FOUND: ' . $blacklists['file_url'] );
                    }
                } else {
                    // Error getting blacklists.
                    return $blacklists;
                }

            // Doing updating here.
            }elseif( $file_urls && $url_count > $current_url ){

                $file_url = 'https://' . str_replace( 'multifiles', $current_url, $file_urls );

                $lines = $this->unpackData( $file_url );
                if( empty( $lines['error'] ) ) {

                    // Do writing to the DB
                    reset( $lines );
                    for( $count_result = 0; current($lines) !== false; ) {
                        $query = "INSERT INTO ".$this->fw_data_table_name."_temp (network, mask, status) VALUES ";
                        for( $i = 0, $values = array(); self::WRITE_LIMIT !== $i && current( $lines ) !== false; $i ++, $count_result ++, next( $lines ) ){
                            $entry = current($lines);
                            if(empty($entry)) {
                                continue;
                            }
                            if ( self::WRITE_LIMIT !== $i ) {
                                // Cast result to int
                                $ip   = preg_replace('/[^\d]*/', '', $entry[0]);
                                $mask = preg_replace('/[^\d]*/', '', $entry[1]);
                                $private = isset($entry[2]) ? $entry[2] : 0;
                            }
                            $values[] = '('. $ip .','. $mask .','. $private .')';
                        }
                        if( ! empty( $values ) ){
                            $query = $query . implode( ',', $values );
                            $this->db->execute( $query );
                        }
                    }
                    $current_url++;
                    $fw_stats['firewall_update_percent'] = round( ( ( (int) $current_url + 1 ) / (int) $url_count ), 2) * 100;
                    $helper::setFwStats( $fw_stats );

                    // Updating continue: Do next remote call.
                    if ( $url_count > $current_url ) {
                        return Helper::http__request__rc_to_host(
                            'sfw_update__write_base',
                            array(
                                'spbc_remote_call_token'  => md5( $this->api_key ),
                                'file_urls'               => str_replace( array( 'http://', 'https://' ), '', $file_urls ),
                                'url_count'               => $url_count,
                                'current_url'             => $current_url,
                                // Additional params
                                'firewall_updating_id'    => $fw_stats['firewall_updating_id'],
                            ),
                            array('get', 'async')
                        );

                    // Updating end: Do finish actions.
                    } else {

                        // Wtite local IP as whitelisted
                        $result = $this->writeDbExclusions();

                        if( empty( $result['error'] ) && is_int( $result ) ) {

                            // @todo We have to handle errors here
                            $this->deleteMainDataTables();
                            // @todo We have to handle errors here
                            $this->renameDataTables();

                            //Files array is empty update sfw stats
                            $helper::SfwUpdate_DoFinisnAction();

                            $fw_stats['firewall_update_percent'] = 0;
                            $fw_stats['firewall_updating_id'] = null;
                            $helper::setFwStats( $fw_stats );

                            return true;

                        } else {
                            return array( 'error' => 'SFW_UPDATE: EXCLUSIONS: ' . $result['error'] );
                        }
                    }
                } else {
                    return array('error' => $lines['error']);
                }
            }else {
                return array('error' => 'SFW_UPDATE WRONG_FILE_URLS');
            }
        } else {
            // Go to init remote call
            return $helper::http__request__rc_to_host(
                'sfw_update',
                array(
                    'spbc_remote_call_token'  => md5( $this->api_key ),
                    'firewall_updating_id'    => $fw_stats['firewall_updating_id'],
                ),
                array( 'get','async' )
            );
        }

    }

    private function getSfwBlacklists( $api_key )
    {
        $api = $this->api;
        $result = $api::method__get_2s_blacklists_db( $api_key, 'multifiles', '3_0' );
        sleep(4);
        return $result;
    }

    private function unpackData( $file_url )
    {
        $helper = $this->helper;
        $file_url = trim( $file_url );

        $response_code = $helper::http__request__get_response_code( $file_url );

        if( empty( $response_code['error'] ) ){

            if( $response_code == 200 || $response_code == 501 ){

                $gz_data = $helper::http__request__get_content( $file_url );

                if( empty( $gz_data['error'] ) ){

                    if( Helper::get_mime_type( $gz_data, 'application/x-gzip' ) ){

                        if( function_exists( 'gzdecode' ) ){

                            $data = gzdecode( $gz_data );

                            if( $data !== false ){

                                return Helper::buffer__parse__csv( $data );

                            }else {
                                return array('error' => 'COULD_DECODE_FILE');
                            }
                        }else {
                            return array('error' => 'FUNCTION_GZ_DECODE_DOES_NOT_EXIST');
                        }
                    }else {
                        return array('error' => 'WRONG_FILE_MIME_TYPE');
                    }
                }else {
                    return array('error' => 'COULD_NOT_GET_IFILE: ' . $gz_data['error']);
                }
            }else {
                return array('error' => 'FILE_BAD_RESPONSE_CODE: ' . (int)$response_code);
            }
        }else {
            return array('error' => 'FILE_COULD_NOT_GET_RESPONSE_CODE: ' . $response_code['error']);
        }
    }

    /**
     * Writing to the DB self IPs
     *
     * @return array|int
     */
    private function writeDbExclusions()
    {
        $query = "INSERT INTO ".$this->fw_data_table_name."_temp (network, mask, status) VALUES ";

        $exclusions = array();

        //Exclusion for servers IP (SERVER_ADDR)
        if ( Server::get('HTTP_HOST') ) {

            // Exceptions for local hosts
            if( ! in_array( Server::get_domain(), array( 'lc', 'loc', 'lh' ) ) ){
                $exclusions[] = Helper::dns__resolve( Server::get( 'HTTP_HOST' ) );
                $exclusions[] = '127.0.0.1';
            }
        }

        foreach ( $exclusions as $exclusion ) {
            if ( Helper::ip__validate( $exclusion ) && sprintf( '%u', ip2long( $exclusion ) ) ) {
                $query .= '(' . sprintf( '%u', ip2long( $exclusion ) ) . ', ' . sprintf( '%u', bindec( str_repeat( '1', 32 ) ) ) . ', 1),';
            }
        }

        if( $exclusions ){
            $sql_result = $this->db->execute( substr( $query, 0, - 1 ) );

            return $sql_result === false
                ? array( 'error' => 'COULD_NOT_WRITE_TO_DB 4: ' . $this->db->get_last_error() )
                : count( $exclusions );
        }

        return 0;
    }

    /**
     * Creatin a temporary updating table
     *
     * @param DB $db database handler
     * @throws \Exception
     */
    private function createTempTables()
    {
        $sql = "SHOW TABLES LIKE '%scleantalk_sfw'";
        $sql = sprintf( $sql, $this->db->prefix ); // Adding current blog prefix
        $result = $this->db->fetch( $sql );

        if( ! $result ){
            $sql = sprintf( Schema::getSchema('sfw'), $this->db->prefix );
            $this->db->execute( $sql );
        }
        $this->db->execute( 'CREATE TABLE IF NOT EXISTS `' . $this->fw_data_table_name . '_temp` LIKE `' . $this->fw_data_table_name . '`' );
        $this->db->execute( 'TRUNCATE TABLE `' . $this->fw_data_table_name . '_temp`' );
    }

    /**
     * Removing a temporary updating table
     *
     * @param DB $db database handler
     */
    private function deleteMainDataTables()
    {
        $this->db->execute( 'DROP TABLE `'. $this->fw_data_table_name . '`');
    }

    /**
     * Renamin a temporary updating table into production table name
     *
     * @param DB $db database handler
     */
    private function renameDataTables()
    {
        $this->db->execute( 'ALTER TABLE `'. $this->fw_data_table_name .'_temp` RENAME `'. $this->fw_data_table_name .'`' );
    }

}