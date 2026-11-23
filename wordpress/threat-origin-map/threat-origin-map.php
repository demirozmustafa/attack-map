<?php
/**
 * Plugin Name:       Threat Origin Map
 * Description:       Firewall / IDS loglarından (pfSense, OPNsense, FortiGate, Suricata) saldırı kaynaklarını canlı dünya haritasında gösterir. Sayfaya eklemek için: [attack_map]
 * Version:           1.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Threat Origin Map
 * License:           GPLv2 or later
 * Text Domain:       threat-origin-map
 */
defined('ABSPATH') || exit;

define('TOM_VERSION', '1.1.0');
define('TOM_FILE', __FILE__);
define('TOM_DIR', plugin_dir_path(__FILE__));
define('TOM_URL', plugin_dir_url(__FILE__));

require_once TOM_DIR . 'includes/mmdb.php';
require_once TOM_DIR . 'includes/core.php';
require_once TOM_DIR . 'includes/rest.php';
require_once TOM_DIR . 'includes/shortcode.php';
if (is_admin()) {
    require_once TOM_DIR . 'includes/admin.php';
}

register_activation_hook(__FILE__, function () {
    tom_install_tables();
    $s = tom_settings();
    if (!$s['ingest_token']) {
        $s['ingest_token'] = wp_generate_password(40, false);
    }
    update_option('tom_settings', $s, true);
    tom_data_dir();
    tom_schedule();
});

register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('tom_daily');
    wp_clear_scheduled_hook('tom_hourly');
});

function tom_schedule() {
    if (!wp_next_scheduled('tom_daily')) {
        wp_schedule_event(time() + 300, 'daily', 'tom_daily');
    }
    if (!wp_next_scheduled('tom_hourly')) {
        wp_schedule_event(time() + 120, 'hourly', 'tom_hourly');
    }
}

add_action('plugins_loaded', function () {
    if ((int) get_option('tom_db_version') !== TOM_DB_VERSION) {
        tom_install_tables();
        tom_schedule();
    }
});

add_action('tom_hourly', 'tom_cleanup');
add_action('tom_daily', 'tom_geo_auto_update');

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    array_unshift($links, '<a href="' . esc_url(admin_url('admin.php?page=threat-origin-map')) . '">Ayarlar</a>');
    return $links;
});
