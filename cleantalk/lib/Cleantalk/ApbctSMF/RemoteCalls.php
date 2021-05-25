<?php

namespace Cleantalk\ApbctSMF;

use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\ApbctSMF\DB;
use Cleantalk\ApbctSMF\Helper as CleantalkHelper;

class RemoteCalls extends \Cleantalk\Common\RemoteCalls {
    /**
     * SFW update
     *
     * @return string
     */
    public function action__sfw_update()
    {
        $firewall = new Firewall(
            $this->api_key,
            DB::getInstance(),
            APBCT_TBL_FIREWALL_LOG
        );
        $firewall->setSpecificHelper( new CleantalkHelper() );
        $fw_updater = $firewall->getUpdater( APBCT_TBL_FIREWALL_DATA );
        return $fw_updater->update();        
    }

    /**
     * SFW send logs
     *
     * @return string
     */
    public function action__sfw_send_logs()
    {
        $firewall = new Firewall(
            $this->api_key,
            DB::getInstance(),
            APBCT_TBL_FIREWALL_LOG
        );
        $firewall->setSpecificHelper( new CleantalkHelper() );
        return $firewall->sendLogs();
    }

    public function action__sfw_update__write_base()
    {
        $firewall = new Firewall(
            $this->api_key,
            DB::getInstance(),
            APBCT_TBL_FIREWALL_LOG
        );
        $firewall->setSpecificHelper( new CleantalkHelper() );
        $fw_updater = $firewall->getUpdater( APBCT_TBL_FIREWALL_DATA );
        return $fw_updater->update(); 
    }
    /**
     * Get available remote calls from the storage.
     *
     * @return array
     */
    protected function getAvailableRcActions()
    {
        global $modSettings;

        $default_rc = array('close_renew_banner' => array('last_call' => 0, 'cooldown' => self::COOLDOWN), 'sfw_update' => array('last_call' => 0, 'cooldown' => self::COOLDOWN), 'sfw_send_logs' => array('last_call' => 0, 'cooldown' => self::COOLDOWN), 'sfw_update__write_base' => array('last_call' => 0, 'cooldown' => 0));
        if (isset($modSettings['cleantalk_remote_calls'])) {
            $remote_calls = json_decode($modSettings['cleantalk_remote_calls'],true);
            return empty(array_diff_key($remote_calls, $default_rc)) ? $remote_calls : $default_rc;
        }
        return $default_rc;
    }

    /**
     * Set last call timestamp and save it to the storage.
     *
     * @param array $action
     * @return void
     */
    protected function setLastCall( $action )
    {
        // TODO: Implement setLastCall() method.
        $remote_calls = $this->getAvailableRcActions();
        $remote_calls[$action]['last_call'] = time();
        updateSettings(array('cleantalk_remote_calls' => json_encode($remote_calls)), false);
    }
}