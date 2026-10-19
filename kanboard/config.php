<?php

// Lab configuration: Kanboard on MariaDB via the routed internal path
// (appnet -> router -> dbnet). The image does not read DB_* environment
// variables — without this override the app silently falls back to the SQLite
// default from config.default.php and the MariaDB segment of this lab would be
// fictional. Uses Kanboard's "defined() or define()" override idiom, the same
// pattern the stock config.php uses for its own overrides.

defined('DB_DRIVER')   or define('DB_DRIVER', 'mysql');
defined('DB_HOSTNAME') or define('DB_HOSTNAME', '172.28.20.10');
defined('DB_NAME')     or define('DB_NAME', 'kanboard');
defined('DB_USERNAME') or define('DB_USERNAME', 'kanboard');
defined('DB_PASSWORD') or define('DB_PASSWORD', 'labdbpw');
defined('DB_PORT')     or define('DB_PORT', 3306);
