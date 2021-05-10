<?php

namespace Cleantalk\ApbctSMF;

class Helper extends \Cleantalk\Common\Helper {

    /**
     * Get fw stats from the storage.
     *
     * @return array
     * @example array( 'firewall_updating' => false, 'firewall_updating_id' => md5(), 'firewall_update_percent' => 0, 'firewall_updating_last_start' => 0 )
     * @important This method must be overloaded in the CMS-based Helper class.
     */
    public static function getFwStats()
    {
        global $modSettings;

        return array('firewall_updating_id' => isset($modSettings['firewall_updating_id']) ? $modSettings['firewall_updating_id'] : null, 'firewall_updating_last_start' => isset($modSettings['firewall_updating_last_start']) ? $modSettings['firewall_updating_last_start'] : 0, 'firewall_update_percent' => isset($modSettings['firewall_update_percent']) ? $modSettings['firewall_update_percent'] : 0);
    }

    /**
     * Save fw stats on the storage.
     *
     * @param array $fw_stats
     * @return bool
     * @important This method must be overloaded in the CMS-based Helper class.
     */
    public static function setFwStats( $fw_stats )
    {
        $settings = array();
        $settings['firewall_updating_id'] = isset($fw_stats['firewall_updating_id']) ? $fw_stats['firewall_updating_id'] : null;
        $settings['firewall_updating_last_start'] = isset($fw_stats['firewall_updating_last_start']) ? $fw_stats['firewall_updating_last_start'] : 0;
        $settings['firewall_update_percent'] = isset($fw_stats['firewall_update_percent']) ? $fw_stats['firewall_update_percent'] : 0;
        updateSettings($settings, false);
    }

    /**
     * Implement here any actions after SFW updating finished.
     *
     * @return void
     */
    public static function SfwUpdate_DoFinisnAction()
    {
        updateSettings(array('sfw_last_update' => time()), false);
    }
}