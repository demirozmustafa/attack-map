<?php
// Runs when the plugin is deleted from WP Admin: removes tables, options and the GeoIP file.
defined('WP_UNINSTALL_PLUGIN') || exit;

global $wpdb;
foreach (['tom_events', 'tom_counts', 'tom_ips'] as $t) {
    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}$t");
}
foreach (['tom_settings', 'tom_status', 'tom_geo_file', 'tom_geo_meta', 'tom_bucket', 'tom_sampled_at', 'tom_demo_last', 'tom_collector', 'tom_db_version', 'tom_ips_count'] as $o) {
    delete_option($o);
}
wp_clear_scheduled_hook('tom_daily');
wp_clear_scheduled_hook('tom_hourly');
$u = wp_upload_dir(null, false);
$dir = trailingslashit($u['basedir']) . 'threat-origin-map';
if (is_dir($dir)) {
    foreach ((array) glob($dir . '/{,.}*', GLOB_BRACE) as $f) {
        if (is_file($f)) {
            @unlink($f);
        }
    }
    @rmdir($dir);
}
