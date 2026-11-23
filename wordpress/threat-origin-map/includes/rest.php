<?php
/**
 * REST API:
 *   GET  /wp-json/tom/v1/live?after=<id>  map data (new events + stats), polled by the map every 2 s
 *   POST /wp-json/tom/v1/ingest           raw log lines from a remote forwarder (Bearer token)
 */
defined('ABSPATH') || exit;

add_action('rest_api_init', function () {
    register_rest_route('tom/v1', '/live', [
        'methods' => 'GET',
        'callback' => 'tom_rest_live',
        'permission_callback' => function () {
            $s = tom_settings();
            return !empty($s['public']) || current_user_can('read');
        },
        'args' => ['after' => ['type' => 'integer', 'default' => 0, 'minimum' => 0]],
    ]);
    register_rest_route('tom/v1', '/ingest', [
        'methods' => 'POST',
        'callback' => 'tom_rest_ingest',
        'permission_callback' => 'tom_rest_ingest_auth',
    ]);
});

function tom_rest_live(WP_REST_Request $req) {
    $s = tom_settings();
    if (!empty($s['demo'])) {
        tom_demo_tick();
    }
    $admin = current_user_can('manage_options');
    $after = (int) $req['after'];
    $res = new WP_REST_Response([
        'site' => ['name' => $s['site_name'], 'lat' => (float) $s['lat'], 'lon' => (float) $s['lon']],
        'events' => tom_events_after($after, !empty($s['mask_ips']) && !$admin),
        'stats' => tom_stats(),
        'admin' => $admin,
        'settings_url' => $admin ? admin_url('admin.php?page=threat-origin-map') : '',
    ]);
    $res->header('Cache-Control', 'no-store, max-age=0');
    return $res;
}

function tom_rest_ingest_auth(WP_REST_Request $req) {
    $s = tom_settings();
    $given = '';
    $auth = (string) $req->get_header('authorization');
    if (stripos($auth, 'Bearer ') === 0) {
        $given = trim(substr($auth, 7));
    } elseif ($req->get_header('x_tom_token')) {
        $given = trim((string) $req->get_header('x_tom_token'));
    }
    if ($given === '' || !$s['ingest_token'] || !hash_equals($s['ingest_token'], $given)) {
        return new WP_Error('tom_bad_token', 'Geçersiz token.', ['status' => 401]);
    }
    return true;
}

function tom_rest_ingest(WP_REST_Request $req) {
    $body = (string) $req->get_body();
    if (strlen($body) > 4 * 1024 * 1024) {
        return new WP_Error('tom_too_large', 'En fazla 4 MB gönderin.', ['status' => 413]);
    }
    $lines = null;
    $first = ltrim($body)[0] ?? '';
    if ($first === '[') {
        $j = json_decode($body, true);
        if (is_array($j)) {
            // JSON array of strings, or of EVE objects (e.g. Fluent Bit / Vector json output)
            $lines = array_map(function ($x) { return is_string($x) ? $x : wp_json_encode($x); }, $j);
        }
    }
    if ($lines === null) {
        $lines = preg_split('/\r?\n/', $body);
    }
    $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'http';
    $c = tom_ingest_lines(array_slice($lines, 0, 20000), 'http:' . $ip);
    return new WP_REST_Response($c, 200);
}
