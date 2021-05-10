<?php

namespace Cleantalk\ApbctSMF;

class Cron extends \Cleantalk\Common\Cron {

    public function saveTasks($tasks)
    {
        updateSettings(array($this->cron_option_name => json_encode(array('last_start' => time(), 'tasks' => $tasks)), false);      
    }

    /**
     * Getting all tasks
     *
     * @return array
     */
    public function getTasks()
    {
        global $modSettings;
        if (isset($modSettings[$this->cron_option_name])) {
            $cron = json_decode($modSettings[$this->cron_option_name], true);
            return (!empty($cron) && isset($cron['tasks'])) ? $cron['tasks'] : null;
        }
        return null;
    }

    /**
     * Save option with tasks
     *
     * @return int timestamp
     */
    public function getCronLastStart()
    {
        global $modSettings;
        if (isset($modSettings[$this->cron_option_name])) {
            $cron = json_decode($modSettings[$this->cron_option_name], true);
            return (!empty($cron) && isset($cron['last_start'])) ? $cron['last_start']: 0;
        }
        return 0;
    }

    /**
     * Save timestamp of running Cron.
     *
     * @return bool
     */
    public function setCronLastStart()
    {
        updateSettings(array($this->cron_option_name => json_encode(array('last_start' => time(), 'tasks' => $this->getTasks())), false);
        return true;
    }
}