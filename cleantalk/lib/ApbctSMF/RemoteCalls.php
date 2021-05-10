<?php

namespace Cleantalk\ApbctSMF;

class RemoteCalls extends \Cleantalk\Common\RemoteCalls {
    /**
     * SFW update
     *
     * @return string
     */
    public function action__sfw_update()
    {
        return apbct_sfw_update( $this->api_key );
    }

    /**
     * SFW send logs
     *
     * @return string
     */
    public function action__sfw_send_logs()
    {
        return apbct_sfw_send_logs( $this->api_key );
    }

    public function action__sfw_update__write_base()
    {
        return apbct_sfw_update( $this->api_key );
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
        if (isset($modSettings['remote_calls'])) {
            $remote_calls = json_decode($modSettings['remote_calls'],true);
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
        updateSettings(array('remote_calls' => json_encode($remote_calls)), false);
    }
}