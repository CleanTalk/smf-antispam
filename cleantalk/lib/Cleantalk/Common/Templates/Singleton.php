<?php

namespace Cleantalk\Common\Templates;

/**
 * Trait Singleton
 *
 * @package CleanTalk
 * @Version 1.1.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

trait Singleton{
    
    public static $instance;
    
    public function __construct(){}
    public function __wakeup(){}
    public function __clone(){}
    
    /**
     * Constructor
     * @return $this
     */
    public static function getInstance(){
        
        $args = func_get_args();
        
        if( ! isset( static::$instance ) || ! $args){
            static::$instance = new static();
            if( ! empty( $args) )
                static::$instance->init( $args );
            else
                static::$instance->init();
        }
        return static::$instance;
    }
    
    /**
     * Alternative constructor
     *
     * @param null $args
     */
    protected function init( $args = null ){
    
    }
    
}
