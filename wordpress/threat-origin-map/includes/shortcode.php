<?php
/**
 * [attack_map]  — optional attributes: height="720" title="..." align="full|wide"
 */
defined('ABSPATH') || exit;

add_shortcode('attack_map', 'tom_shortcode');

function tom_shortcode($atts) {
    $s = tom_settings();
    $a = shortcode_atts(['height' => '720', 'title' => $s['title'], 'align' => ''], $atts, 'attack_map');
    $align = in_array($a['align'], ['full', 'wide'], true) ? ' align' . $a['align'] : '';
    if (empty($s['public']) && !is_user_logged_in()) {
        return '<p class="tom-locked">Saldırı haritası yalnızca giriş yapmış kullanıcılara açık.</p>';
    }
    $h = (int) $a['height'];
    $h = $h >= 420 && $h <= 2000 ? $h : 720;

    wp_enqueue_style('tom-fonts', 'https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap', [], null);
    wp_enqueue_style('tom-map', TOM_URL . 'assets/map.css', [], TOM_VERSION);
    wp_enqueue_script('tom-d3', 'https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js', [], null, true);
    wp_enqueue_script('tom-topojson', 'https://cdn.jsdelivr.net/npm/topojson-client@3.1.0/dist/topojson-client.min.js', [], null, true);
    wp_enqueue_script('tom-map', TOM_URL . 'assets/map.js', ['tom-d3', 'tom-topojson'], TOM_VERSION, true);
    wp_localize_script('tom-map', 'TOM_CFG', [
        'api' => esc_url_raw(rest_url('tom/v1/live')),
        'nonce' => wp_create_nonce('wp_rest'),
        'land' => TOM_URL . 'assets/land-110m.json',
    ]);

    ob_start();
    ?>
<div class="tom-root<?php echo esc_attr($align); ?>" style="--tom-h:<?php echo (int) $h; ?>px">
  <div class="tom-app">
    <header class="tom-head">
      <div class="tom-brand">
        <span class="tom-eyebrow" data-r="eyebrow">Perimeter sensor · inbound blocks and IDS alerts</span>
        <h2 class="tom-h1"><span data-r="title"><?php echo esc_html($a['title']); ?></span> <span class="tom-live" data-r="live" data-s="connecting"><i></i><span data-r="liveTxt">CONNECTING</span></span></h2>
      </div>
      <div class="tom-kpis">
        <div class="tom-kpi"><b data-r="kRate">–</b><span>Attacks / min</span></div>
        <div class="tom-kpi"><b data-r="kTotal">–</b><span>Today</span></div>
        <div class="tom-kpi"><b data-r="kIps">–</b><span>Unique IPs</span></div>
        <div class="tom-kpi"><b data-r="kCountries">–</b><span>Countries</span></div>
      </div>
      <div class="tom-ctrls">
        <button type="button" class="tom-btn" data-r="pause">Pause</button>
        <button type="button" class="tom-btn" data-r="full">Full screen</button>
        <a class="tom-btn" data-r="settings" hidden>Settings</a>
      </div>
    </header>
    <section class="tom-stage" aria-label="World map of attack sources">
      <canvas data-r="map"></canvas>
      <canvas data-r="fx"></canvas>
      <div class="tom-sim" data-r="sampleNote"></div>
      <div class="tom-banner" data-r="banner" hidden></div>
      <div class="tom-legend" data-r="legend"></div>
    </section>
    <aside class="tom-side">
      <div class="tom-panel">
        <h3>Top source countries <small>last 15 min</small></h3>
        <div class="tom-rows" data-r="top"><p class="tom-note">Waiting for the first events…</p></div>
      </div>
      <div class="tom-panel">
        <h3>Attack types <small data-r="typeTotal">last 15 min</small></h3>
        <div class="tom-stack" data-r="stack"></div>
        <div class="tom-types" data-r="types"></div>
      </div>
      <div class="tom-panel tom-feed">
        <h3>Event feed <small>newest first</small></h3>
        <div class="tom-feedbox">
          <table>
            <thead><tr><th>Time</th><th>Source</th><th>CC</th><th>Type</th><th>Port</th></tr></thead>
            <tbody data-r="feed"></tbody>
          </table>
        </div>
      </div>
    </aside>
  </div>
</div>
    <?php
    return ob_get_clean();
}
