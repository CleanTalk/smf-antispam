<?php
add_integration_function('integrate_load_theme', 'cleantalk_load');

// flush settings cache
cache_put_data('modSettings', null, 1);