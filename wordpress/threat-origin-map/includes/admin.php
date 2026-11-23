<?php
/**
 * WP Admin → Saldırı Haritası: status, device setup, settings, GeoIP. All actions go through admin-post.php with nonces.
 */
defined('ABSPATH') || exit;

add_action('admin_menu', function () {
    add_menu_page('Saldırı Haritası', 'Saldırı Haritası', 'manage_options', 'threat-origin-map', 'tom_admin_page', 'dashicons-location-alt', 81);
});

/* ------------------------------------------------------------------ actions */

function tom_admin_guard($action) {
    if (!current_user_can('manage_options')) {
        wp_die('Yetkiniz yok.', 403);
    }
    check_admin_referer($action);
}

function tom_admin_back($msg, $type = 'success', $anchor = '') {
    set_transient('tom_notice_' . get_current_user_id(), [$msg, $type], 60);
    wp_safe_redirect(admin_url('admin.php?page=threat-origin-map') . ($anchor ? '#' . $anchor : ''));
    exit;
}

add_action('admin_post_tom_save', function () {
    tom_admin_guard('tom_save');
    $in = wp_unslash($_POST);
    $s = tom_settings();
    $err = [];

    $s['site_name'] = mb_substr(sanitize_text_field($in['site_name'] ?? ''), 0, 60) ?: 'Site';
    $s['title'] = mb_substr(sanitize_text_field($in['title'] ?? ''), 0, 80) ?: 'Where attackers come from';
    foreach (['lat' => 90, 'lon' => 180] as $k => $lim) {
        $v = str_replace(',', '.', trim((string) ($in[$k] ?? '')));
        if (!is_numeric($v) || abs((float) $v) > $lim) {
            $err[] = ($k === 'lat' ? 'Enlem' : 'Boylam') . " -$lim ile $lim arasında olmalı.";
        } else {
            $s[$k] = round((float) $v, 4);
        }
    }
    $senders = [];
    foreach (preg_split('/[\s,]+/', (string) ($in['allowed_senders'] ?? ''), -1, PREG_SPLIT_NO_EMPTY) as $e) {
        $parts = explode('/', $e, 2);
        $ok = filter_var($parts[0], FILTER_VALIDATE_IP)
            && (!isset($parts[1]) || (ctype_digit($parts[1]) && (int) $parts[1] <= (strpos($parts[0], ':') !== false ? 128 : 32)));
        if ($ok) {
            $senders[] = $e;
        } else {
            $err[] = 'Geçersiz IP/ağ: ' . esc_html($e);
        }
    }
    $s['allowed_senders'] = implode("\n", array_unique($senders));
    foreach (TOM_SOURCES as $k) {
        $s['sources'][$k] = empty($in['sources'][$k]) ? 0 : 1;
    }
    $eve = trim((string) ($in['eve_file'] ?? ''));
    if ($eve !== '' && (strpos($eve, '/') !== 0 || strpos($eve, '..') !== false || !preg_match('/\.json$/', $eve))) {
        $err[] = 'eve.json yolu / ile başlayan tam bir .json dosya yolu olmalı.';
    } else {
        $s['eve_file'] = $eve;
    }
    $num = function ($k, $lo, $hi, $label) use ($in, &$s, &$err) {
        $v = $in[$k] ?? '';
        if (!is_numeric($v) || (int) $v < $lo || (int) $v > $hi) {
            $err[] = "$label $lo–$hi arasında olmalı.";
        } else {
            $s[$k] = (int) $v;
        }
    };
    $num('syslog_port', 1024, 65535, 'Syslog portu');
    $num('max_eps', 1, 500, 'Saniyedeki en fazla yay');
    $num('retention_days', 1, 90, 'Saklama süresi');
    foreach (['public', 'mask_ips', 'demo', 'geo_auto'] as $k) {
        $s[$k] = empty($in[$k]) ? 0 : 1;
    }
    $acct = trim((string) ($in['geo_account'] ?? ''));
    if ($acct !== '' && !ctype_digit($acct)) {
        $err[] = 'MaxMind Account ID yalnızca rakam olmalı.';
    } else {
        $s['geo_account'] = $acct;
    }
    $key = trim((string) ($in['geo_key'] ?? ''));
    if ($key !== '') { // empty field = keep the stored key
        if (!preg_match('/^[A-Za-z0-9_]{6,64}$/', $key)) {
            $err[] = 'License Key biçimi hatalı.';
        } else {
            $s['geo_key'] = $key;
        }
    }
    if (!empty($in['geo_key_clear'])) {
        $s['geo_key'] = '';
    }
    if ($err) {
        tom_admin_back('Kaydedilmedi: ' . implode(' ', $err), 'error');
    }
    update_option('tom_settings', $s, true);
    wp_cache_delete('tom_stats', 'tom');
    tom_admin_back('Ayarlar kaydedildi.');
});

add_action('admin_post_tom_geo_download', function () {
    tom_admin_guard('tom_geo_download');
    try {
        tom_geo_download();
        $m = get_option('tom_geo_meta');
        tom_admin_back('GeoIP veritabanı indirildi: ' . $m['type'] . ' · ' . $m['built'], 'success', 'geoip');
    } catch (Exception $e) {
        $m = get_option('tom_geo_meta');
        $m = is_array($m) ? $m : [];
        $m['error'] = $e->getMessage();
        update_option('tom_geo_meta', $m, false);
        tom_admin_back($e->getMessage(), 'error', 'geoip');
    }
});

add_action('admin_post_tom_geo_upload', function () {
    tom_admin_guard('tom_geo_upload');
    $f = $_FILES['mmdb'] ?? null;
    if (!$f || !empty($f['error']) || !is_uploaded_file($f['tmp_name'])) {
        $code = $f['error'] ?? 0;
        $msg = in_array($code, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true)
            ? 'Dosya PHP yükleme sınırını aşıyor (upload_max_filesize = ' . ini_get('upload_max_filesize') . '). CloudPanel → Site → PHP Settings bölümünden artırın.'
            : 'Dosya yüklenemedi.';
        tom_admin_back($msg, 'error', 'geoip');
    }
    $tmp = tom_tempnam('upload.mmdb');
    move_uploaded_file($f['tmp_name'], $tmp);
    try {
        tom_geo_install($tmp);
        $m = get_option('tom_geo_meta');
        tom_admin_back('GeoIP veritabanı yüklendi: ' . $m['type'] . ' · ' . $m['built'], 'success', 'geoip');
    } catch (Exception $e) {
        tom_admin_back($e->getMessage(), 'error', 'geoip');
    } finally {
        @unlink($tmp);
    }
});

add_action('admin_post_tom_test_event', function () {
    tom_admin_guard('tom_test_event');
    $r = tom_inject_synthetic(3, 'test');
    tom_admin_back($r['stored'] ? 'Haritaya 3 test saldırısı gönderildi (uydurma konum).' : 'Test olayı kaydedilemedi (saniyedeki yay sınırı dolmuş olabilir).', $r['stored'] ? 'success' : 'warning', 'status');
});

add_action('admin_post_tom_allow_sender', function () {
    tom_admin_guard('tom_allow_sender');
    $ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        tom_admin_back('Geçersiz IP.', 'error', 'status');
    }
    $s = tom_settings();
    $list = preg_split('/[\s,]+/', $s['allowed_senders'], -1, PREG_SPLIT_NO_EMPTY);
    $list[] = $ip;
    tom_update_settings(['allowed_senders' => implode("\n", array_unique($list))]);
    tom_admin_back("$ip izinli göndericilere eklendi. Toplayıcı birkaç saniye içinde kabul etmeye başlar.", 'success', 'status');
});

add_action('admin_post_tom_regen_token', function () {
    tom_admin_guard('tom_regen_token');
    tom_update_settings(['ingest_token' => wp_generate_password(40, false)]);
    tom_admin_back('Yeni HTTP token oluşturuldu. Eski token artık çalışmaz.', 'success', 'connect');
});

add_action('admin_post_tom_reset', function () {
    tom_admin_guard('tom_reset');
    global $wpdb;
    foreach (tom_tables() as $t) {
        $wpdb->query("TRUNCATE TABLE $t");
    }
    delete_option('tom_status');
    delete_option('tom_sampled_at');
    wp_cache_delete('tom_stats', 'tom');
    tom_admin_back('Tüm olaylar ve sayaçlar silindi.', 'success', 'status');
});

/* ------------------------------------------------------------------ page */

function tom_server_address() {
    $host = wp_parse_url(home_url(), PHP_URL_HOST);
    $ip = $host ? gethostbyname($host) : '';
    if (!$ip || $ip === $host || !tom_is_public_ip($ip)) {
        $ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : '';
    }
    return $ip ?: 'SUNUCU_IP';
}

function tom_service_unit() {
    $owner = null;
    if (function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid(@fileowner(ABSPATH . 'wp-config.php') ?: @fileowner(ABSPATH . 'index.php'));
        $owner = $pw['name'] ?? null;
    }
    $owner = $owner ?: (get_current_user() ?: 'SITE_KULLANICISI');
    $php = 'php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    $host = preg_replace('/[^a-z0-9]+/', '-', strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST)));
    $name = 'threat-origin-map-' . trim($host, '-');
    $script = TOM_DIR . 'collector/tom-collector.php';
    $cmd = "sudo tee /etc/systemd/system/$name.service > /dev/null <<'EOF'
[Unit]
Description=Threat Origin Map syslog collector ($host)
After=network-online.target mysql.service mariadb.service
Wants=network-online.target

[Service]
User=$owner
ExecStart=/usr/bin/env $php $script
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now $name
systemctl status $name --no-pager";
    return [$name, $cmd, $php];
}

function tom_ago($ts) {
    if (!$ts) {
        return '—';
    }
    $d = time() - (int) $ts;
    if ($d < 60) {
        return $d . ' sn önce';
    }
    if ($d < 3600) {
        return floor($d / 60) . ' dk önce';
    }
    return wp_date('d.m.Y H:i', (int) $ts);
}

function tom_admin_page() {
    if (!current_user_can('manage_options')) {
        return;
    }
    $s = tom_settings();
    $st = get_option('tom_status');
    $st = is_array($st) ? $st : [];
    $col = tom_collector_state();
    $geo = tom_geo_reader();
    $gm = get_option('tom_geo_meta');
    $gm = is_array($gm) ? $gm : [];
    $notice = get_transient('tom_notice_' . get_current_user_id());
    delete_transient('tom_notice_' . get_current_user_id());
    $srv = tom_server_address();
    $port = (int) $s['syslog_port'];
    [$svc, $unit, $php] = tom_service_unit();
    $form = function ($action, $label, $class = 'button', $extra = '', $confirm = '') {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline"' . ($confirm ? ' onsubmit="return confirm(\'' . esc_js($confirm) . '\')"' : '') . '>';
        wp_nonce_field($action);
        echo '<input type="hidden" name="action" value="' . esc_attr($action) . '">' . $extra;
        echo '<button class="' . esc_attr($class) . '">' . esc_html($label) . '</button></form>';
    };
    $presets = [
        'İstanbul' => [41.01, 28.98], 'Ankara' => [39.93, 32.86], 'İzmir' => [38.42, 27.14], 'Frankfurt' => [50.11, 8.68],
        'Amsterdam' => [52.37, 4.89], 'London' => [51.51, -0.13], 'Paris' => [48.86, 2.35], 'Helsinki' => [60.17, 24.94],
        'New York' => [40.71, -74.01], 'Ashburn' => [39.04, -77.49], 'Singapore' => [1.35, 103.82],
    ];
    ?>
<div class="wrap tom-admin">
  <h1>Saldırı Haritası</h1>
  <p class="tom-lead">Haritayı bir sayfaya eklemek için sayfa düzenleyicide <strong>Kısa kod</strong> bloğu ekleyip <code>[attack_map]</code> yazın. Yükseklik için: <code>[attack_map height="800"]</code></p>
  <?php if ($notice): ?>
    <div class="notice notice-<?php echo esc_attr($notice[1]); ?> is-dismissible"><p><?php echo esc_html($notice[0]); ?></p></div>
  <?php endif; ?>
  <nav class="tom-jump"><a href="#status">Durum</a><a href="#connect">Cihaz bağlama</a><a href="#settings">Ayarlar</a><a href="#geoip">GeoIP</a></nav>

  <section class="tom-card" id="status">
    <h2>Durum</h2>
    <div class="tom-kv">
      <div><span>Toplayıcı servisi</span><b class="<?php echo $col['running'] ? 'ok' : 'bad'; ?>"><?php echo $col['running'] ? 'Çalışıyor' : ($col['seen'] ? 'Durmuş' : 'Kurulmadı'); ?></b>
        <em><?php echo $col['seen'] ? 'UDP ' . (int) ($col['port'] ?? 0) . ' · son sinyal ' . esc_html(tom_ago($col['last'])) : 'Aşağıdaki “Cihaz bağlama” 1. adım'; ?></em></div>
      <div><span>GeoIP</span><b class="<?php echo $geo ? 'ok' : 'bad'; ?>"><?php echo $geo ? 'Hazır' : 'Yok'; ?></b>
        <em><?php echo $geo ? esc_html(($gm['type'] ?? '') . ' · ' . ($gm['built'] ?? '')) : 'GeoIP bölümüne bakın'; ?></em></div>
      <div><span>Alınan satır</span><b><?php echo number_format_i18n($st['received'] ?? 0); ?></b><em>işlenen <?php echo number_format_i18n($st['parsed'] ?? 0); ?> · atlanan <?php echo number_format_i18n($st['ignored'] ?? 0); ?></em></div>
      <div><span>Haritaya konamayan</span><b><?php echo number_format_i18n(($st['unlocated'] ?? 0) + ($st['private'] ?? 0)); ?></b><em>konumsuz <?php echo number_format_i18n($st['unlocated'] ?? 0); ?> · özel IP <?php echo number_format_i18n($st['private'] ?? 0); ?></em></div>
      <div><span>Reddedilen paket</span><b><?php echo number_format_i18n($st['rejected'] ?? 0); ?></b><em>izinli listede olmayan cihazlardan</em></div>
    </div>
    <h3>Log gönderen cihazlar</h3>
    <?php if (empty($st['senders'])): ?>
      <p class="description">Henüz log gelmedi. Toplayıcıyı kurup cihazınızı ayarlayınca burada görünür.</p>
    <?php else: ?>
      <table class="widefat striped tom-table"><thead><tr><th>Gönderen</th><th>Satır</th><th>İşlenen</th><th>Son</th><th>Durum</th></tr></thead><tbody>
      <?php foreach ($st['senders'] as $ip => $x): ?>
        <tr><td><code><?php echo esc_html($ip); ?></code></td><td><?php echo number_format_i18n($x['count']); ?></td><td><?php echo number_format_i18n($x['parsed']); ?></td>
          <td><?php echo esc_html(tom_ago($x['last'])); ?></td>
          <td><?php if (!empty($x['allowed'])) {
              echo '<span class="ok">İzinli</span>';
          } else {
              echo '<span class="bad">Reddedildi</span> ';
              $form('tom_allow_sender', 'İzin ver', 'button button-small', '<input type="hidden" name="ip" value="' . esc_attr($ip) . '">');
          } ?></td></tr>
      <?php endforeach; ?>
      </tbody></table>
    <?php endif; ?>
    <p class="tom-row">
      <?php $form('tom_test_event', 'Test saldırısı gönder'); ?>
      <?php $form('tom_reset', 'Olayları ve sayaçları sıfırla', 'button-link button-link-delete', '', 'Tüm olaylar ve sayaçlar silinsin mi?'); ?>
    </p>
  </section>

  <section class="tom-card" id="connect">
    <h2>Cihaz bağlama</h2>
    <h3>1. Toplayıcı servisini kurun <small>(bir kez, SSH ile)</small></h3>
    <p>PHP-FPM sürekli açık kalıp UDP dinleyemez. Bu yüzden eklentinin içindeki küçük toplayıcı bir systemd servisi olarak çalışır.
      Syslog'u <strong>UDP <?php echo (int) $port; ?></strong> portundan alır, ayarları bu sayfadan okur ve doğrudan WordPress veritabanına yazar.
      Sunucuya <code>root</code> ya da sudo yetkili kullanıcıyla SSH ile bağlanıp şunu yapıştırın:</p>
    <div class="tom-code"><button type="button" class="button button-small tom-copy">Kopyala</button><pre><?php echo esc_html($unit); ?></pre></div>
    <p class="description">Servis <code><?php echo esc_html($php); ?></code> komutunu kullanır; CloudPanel'de sitenin PHP sürümüyle aynıdır. Komut bulunamazsa <code>ls /usr/bin/php*</code> ile mevcut sürümü görüp satırı düzeltin.
      Loglar: <code>journalctl -u <?php echo esc_html($svc); ?> -f</code>. Eklentiyi güncelledikten sonra: <code>sudo systemctl restart <?php echo esc_html($svc); ?></code></p>

    <h3>2. Portu açın</h3>
    <p>CloudPanel → <strong>Admin Area → Security → Firewall</strong> bölümünde <strong>UDP <?php echo (int) $port; ?></strong> için kural ekleyin. Kaynak olarak yalnızca firewall cihazınızın dış IP'sini yazın.
      Panel UDP seçeneği sunmuyorsa SSH'tan ekleyin (CloudPanel'in güvenlik duvarı ufw kullanır):</p>
    <div class="tom-code"><button type="button" class="button button-small tom-copy">Kopyala</button><pre>sudo ufw allow from CIHAZ_IP to any port <?php echo (int) $port; ?> proto udp</pre></div>
    <p class="description">Sunucunuz bir bulut sağlayıcısındaysa (Hetzner, AWS, DigitalOcean…), sağlayıcının kendi güvenlik duvarında da aynı kuralı açın.</p>

    <h3>3. Cihazı ayarlayın</h3>
    <p>Sunucu adresi: <code><?php echo esc_html($srv); ?></code> · Port: <code><?php echo (int) $port; ?></code> (UDP).
      <span class="description">Alan adınız Cloudflare proxy arkasındaysa burada Cloudflare IP'si görünebilir; o durumda sunucunun gerçek IP'sini kullanın.</span></p>
    <div class="tom-tabs" role="tablist">
      <button type="button" role="tab" aria-selected="true" data-tab="pf">pfSense</button>
      <button type="button" role="tab" aria-selected="false" data-tab="opn">OPNsense</button>
      <button type="button" role="tab" aria-selected="false" data-tab="forti">FortiGate</button>
      <button type="button" role="tab" aria-selected="false" data-tab="suri">Suricata</button>
      <button type="button" role="tab" aria-selected="false" data-tab="http">HTTP (gelişmiş)</button>
    </div>
    <div class="tom-tab" data-pane="pf"><ol>
      <li><strong>Status → System Logs → Settings</strong></li>
      <li><em>Enable Remote Logging</em> kutusunu işaretleyin.</li>
      <li><em>Remote log servers</em>: <code><?php echo esc_html("$srv:$port"); ?></code></li>
      <li><em>Remote Syslog Contents</em>: <strong>Firewall Events</strong>. Kaydedin.</li>
      <li>Yalnızca loglanan kurallar gelir. WAN'daki engelleme kurallarında <em>Log packets that are handled by this rule</em> açık olsun. Varsayılan engelleme kuralının logu: <strong>Status → System Logs → Settings → Log firewall default blocks</strong>.</li>
    </ol></div>
    <div class="tom-tab" data-pane="opn" hidden><ol>
      <li><strong>System → Settings → Logging → Remote</strong> → <strong>+</strong></li>
      <li><em>Transport</em>: UDP(4) · <em>Applications</em>: <strong>filter (filterlog)</strong> · <em>Levels</em>: hepsi</li>
      <li><em>Hostname</em>: <code><?php echo esc_html($srv); ?></code> · <em>Port</em>: <code><?php echo (int) $port; ?></code> · <em>RFC5424</em> açık ya da kapalı olabilir.</li>
      <li>Kaydedin. WAN engelleme kurallarında <em>Log</em> açık olmalı.</li>
    </ol></div>
    <div class="tom-tab" data-pane="forti" hidden>
      <p>CLI'da çalıştırın. Format <code>default</code> kalmalı; CEF kullanılırsa loglar tanınmaz.</p>
      <div class="tom-code"><button type="button" class="button button-small tom-copy">Kopyala</button><pre>config log syslogd setting
    set status enable
    set server "<?php echo esc_html($srv); ?>"
    set mode udp
    set port <?php echo (int) $port; ?>

    set format default
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set anomaly enable
end</pre></div>
      <p class="description">Engellenen trafiğin gelmesi için ilgili policy'lerde <em>Log Violation Traffic</em> açık olmalı. IPS ve WAF logları da gelir.</p>
    </div>
    <div class="tom-tab" data-pane="suri" hidden>
      <p><strong>Suricata aynı sunucudaysa:</strong> aşağıdaki Ayarlar bölümünde <em>eve.json yolu</em>nu girin (ör. <code>/var/log/suricata/eve.json</code>). Toplayıcı dosyayı izler. Servis kullanıcısının dosyayı okuyabilmesi gerekir.</p>
      <p><strong>Başka bir makinedeyse:</strong> <code>suricata.yaml</code> içinde EVE çıktısını syslog'a yönlendirin:</p>
      <div class="tom-code"><button type="button" class="button button-small tom-copy">Kopyala</button><pre>outputs:
  - eve-log:
      enabled: yes
      filetype: syslog
      identity: "suricata"
      facility: local5
      types:
        - alert</pre></div>
      <p>Ardından o makinenin rsyslog'una şu satırı ekleyin: <code>local5.* @<?php echo esc_html("$srv:$port"); ?></code></p>
    </div>
    <div class="tom-tab" data-pane="http" hidden>
      <p>UDP gönderemeyen kaynaklar logları HTTPS ile de gönderebilir. Her satır bir log satırıdır; JSON dizi de kabul edilir. Örnek:</p>
      <div class="tom-code"><button type="button" class="button button-small tom-copy">Kopyala</button><pre>curl -X POST <?php echo esc_html(rest_url('tom/v1/ingest')); ?> \
  -H "Authorization: Bearer <?php echo esc_html($s['ingest_token']); ?>" \
  -H "Content-Type: text/plain" --data-binary @loglar.txt</pre></div>
      <p class="tom-row"><?php $form('tom_regen_token', 'Yeni token oluştur', 'button', '', 'Eski token geçersiz olacak. Devam edilsin mi?'); ?>
        <span class="description">Token gizli tutulmalı; elinde olan herkes haritaya olay yazabilir.</span></p>
    </div>
  </section>

  <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" id="settings">
    <?php wp_nonce_field('tom_save'); ?>
    <input type="hidden" name="action" value="tom_save">

    <section class="tom-card">
      <h2>Konum ve başlık</h2>
      <p class="description">Haritadaki hedef nokta, yani korunan sunucu veya ofis.</p>
      <div class="tom-grid">
        <label>Hazır konum<select id="tom-preset"><option value="">Seçin…</option>
          <?php foreach ($presets as $n => [$la, $lo]): ?><option data-lat="<?php echo esc_attr($la); ?>" data-lon="<?php echo esc_attr($lo); ?>"><?php echo esc_html($n); ?></option><?php endforeach; ?>
        </select></label>
        <label>Konum adı<input type="text" name="site_name" id="tom-name" value="<?php echo esc_attr($s['site_name']); ?>" maxlength="60"></label>
        <label>Enlem<input type="text" name="lat" id="tom-lat" value="<?php echo esc_attr($s['lat']); ?>" inputmode="decimal"></label>
        <label>Boylam<input type="text" name="lon" id="tom-lon" value="<?php echo esc_attr($s['lon']); ?>" inputmode="decimal"></label>
        <label class="wide">Harita başlığı<input type="text" name="title" value="<?php echo esc_attr($s['title']); ?>" maxlength="80"></label>
      </div>
    </section>

    <section class="tom-card">
      <h2>Log kaynakları</h2>
      <div class="tom-grid">
        <label class="wide">İzinli göndericiler <small>(IP veya ağ, satır başına bir tane. Boş bırakılırsa her yerden kabul edilir; o durumda portu güvenlik duvarında kısıtlayın.)</small>
          <textarea name="allowed_senders" rows="3" placeholder="203.0.113.1&#10;198.51.100.0/24"><?php echo esc_textarea($s['allowed_senders']); ?></textarea></label>
        <fieldset class="wide"><legend>Kabul edilen log türleri</legend>
          <label class="tom-check"><input type="checkbox" name="sources[filterlog]" value="1" <?php checked($s['sources']['filterlog']); ?>> pfSense / OPNsense filterlog <small>(gelen + engellenen)</small></label>
          <label class="tom-check"><input type="checkbox" name="sources[suricata]" value="1" <?php checked($s['sources']['suricata']); ?>> Suricata EVE alert</label>
          <label class="tom-check"><input type="checkbox" name="sources[fortigate]" value="1" <?php checked($s['sources']['fortigate']); ?>> FortiGate <small>(deny, IPS, anomaly, WAF)</small></label>
        </fieldset>
        <label>Syslog UDP portu<input type="number" name="syslog_port" min="1024" max="65535" value="<?php echo (int) $s['syslog_port']; ?>"></label>
        <label>Suricata eve.json yolu <small>(isteğe bağlı)</small><input type="text" name="eve_file" value="<?php echo esc_attr($s['eve_file']); ?>" placeholder="/var/log/suricata/eve.json"></label>
      </div>
      <p class="description">Port değişikliğini toplayıcı birkaç saniye içinde uygular; güvenlik duvarı kuralını da güncellemeyi unutmayın.</p>
    </section>

    <section class="tom-card" id="geoip">
      <h2>GeoIP</h2>
      <p>IP adreslerini ülke ve konuma çevirmek için ücretsiz MaxMind GeoLite2-City veritabanı gerekir.
        <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener">Ücretsiz hesap açın</a>, ardından <em>Manage License Keys</em> bölümünden bir anahtar oluşturun.</p>
      <p>Durum: <?php echo $geo ? '<span class="ok">Hazır</span> · ' . esc_html(($gm['type'] ?? '') . ' · ' . ($gm['built'] ?? '') . ' · güncelleme ' . tom_ago($gm['updated'] ?? 0)) : '<span class="bad">Veritabanı yok</span>'; ?>
        <?php if (!empty($gm['error'])): ?><br><span class="bad">Son hata: <?php echo esc_html($gm['error']); ?></span><?php endif; ?></p>
      <div class="tom-grid">
        <label>Account ID<input type="text" name="geo_account" value="<?php echo esc_attr($s['geo_account']); ?>" inputmode="numeric" autocomplete="off"></label>
        <label>License Key<input type="password" name="geo_key" value="" placeholder="<?php echo $s['geo_key'] ? 'Kayıtlı (değiştirmek için yazın)' : ''; ?>" autocomplete="new-password"></label>
        <label class="tom-check wide"><input type="checkbox" name="geo_auto" value="1" <?php checked($s['geo_auto']); ?>> Haftalık otomatik güncelle <small>(WP-Cron)</small></label>
        <?php if ($s['geo_key']): ?><label class="tom-check wide"><input type="checkbox" name="geo_key_clear" value="1"> Kayıtlı anahtarı sil</label><?php endif; ?>
      </div>
      <p class="description">Anahtarı girdikten sonra önce <strong>Kaydet</strong>'e, sonra aşağıdaki <strong>Şimdi indir</strong>'e basın.</p>
    </section>

    <section class="tom-card">
      <h2>Görünüm ve erişim</h2>
      <div class="tom-grid">
        <label class="tom-check wide"><input type="checkbox" name="public" value="1" <?php checked($s['public']); ?>> Haritayı ziyaretçilere göster <small>(kapalıysa yalnızca giriş yapmış kullanıcılar görür)</small></label>
        <label class="tom-check wide"><input type="checkbox" name="mask_ips" value="1" <?php checked($s['mask_ips']); ?>> Ziyaretçilere IP adreslerinin son kısmını gizle <small>(yöneticiler tam IP görür)</small></label>
        <label class="tom-check wide"><input type="checkbox" name="demo" value="1" <?php checked($s['demo']); ?>> Demo verisi <small>(gerçek log yokken haritayı denemek için; haritada “Demo data” yazar)</small></label>
        <label>Saniyedeki en fazla yay<input type="number" name="max_eps" min="1" max="500" value="<?php echo (int) $s['max_eps']; ?>"></label>
        <label>Olay saklama süresi (gün)<input type="number" name="retention_days" min="1" max="90" value="<?php echo (int) $s['retention_days']; ?>"></label>
      </div>
      <p class="description">Yoğun saldırıda tüm olaylar sayılır ama haritaya en fazla bu kadar yay çizilir. Böylece veritabanı şişmez.</p>
    </section>

    <div class="tom-savebar"><?php submit_button('Kaydet', 'primary', 'submit', false); ?></div>
  </form>

  <section class="tom-card">
    <h2>GeoIP veritabanı işlemleri</h2>
    <p class="tom-row"><?php $form('tom_geo_download', 'Şimdi indir', 'button button-secondary'); ?>
      <span class="description">MaxMind'dan yaklaşık 60 MB indirilir; 10–60 saniye sürebilir.</span></p>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data" class="tom-row">
      <?php wp_nonce_field('tom_geo_upload'); ?><input type="hidden" name="action" value="tom_geo_upload">
      <input type="file" name="mmdb" accept=".mmdb" required> <button class="button">.mmdb dosyası yükle</button>
      <span class="description">Sunucu internete çıkamıyorsa: GeoLite2-City.mmdb (en fazla <?php echo esc_html(ini_get('upload_max_filesize')); ?>)</span>
    </form>
  </section>
</div>
<style>
.tom-admin{max-width:1040px}
.tom-lead{font-size:14px}
.tom-jump{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 4px}
.tom-jump a{border:1px solid #c3c4c7;border-radius:3px;padding:3px 9px;text-decoration:none;background:#fff}
.tom-card{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:4px 20px 16px;margin:16px 0;scroll-margin-top:48px}
.tom-card h2{font-size:1.25em}
.tom-card h3{margin:1.4em 0 .5em}
.tom-card h3 small{font-weight:400;color:#646970}
.tom-kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}
.tom-kv>div{border:1px solid #dcdcde;border-radius:4px;padding:10px 12px;background:#f6f7f7;display:grid;gap:2px}
.tom-kv span{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#646970}
.tom-kv b{font-size:18px}
.tom-kv em{font-style:normal;color:#646970;font-size:12px}
.tom-admin .ok{color:#008a20;font-weight:600}
.tom-admin .bad{color:#d63638;font-weight:600}
.tom-table{max-width:760px}
.tom-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.tom-code{position:relative;max-width:900px}
.tom-code pre{background:#1d2327;color:#f0f0f1;padding:14px;border-radius:4px;overflow-x:auto;margin:6px 0;font-size:12.5px;line-height:1.5}
.tom-code .tom-copy{position:absolute;top:8px;right:8px}
.tom-tabs{display:flex;gap:2px;border-bottom:1px solid #c3c4c7;margin-top:10px;flex-wrap:wrap}
.tom-tabs button{background:none;border:0;border-bottom:2px solid transparent;padding:8px 12px;cursor:pointer;font-size:13px;color:#50575e}
.tom-tabs button[aria-selected=true]{border-bottom-color:#2271b1;color:#1d2327;font-weight:600}
.tom-tab{padding:4px 0}
.tom-tab ol{line-height:1.7}
.tom-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px 18px;margin:10px 0}
.tom-grid>label,.tom-grid>fieldset{display:grid;gap:4px;font-weight:600;min-width:0}
.tom-grid small{font-weight:400;color:#646970}
.tom-grid input[type=text],.tom-grid input[type=number],.tom-grid input[type=password],.tom-grid select,.tom-grid textarea{width:100%;max-width:none;font-weight:400}
.tom-grid .wide{grid-column:1/-1}
.tom-grid legend{font-weight:600;margin-bottom:4px}
.tom-check{display:flex!important;align-items:center;gap:8px;font-weight:400!important}
.tom-savebar{position:sticky;bottom:0;background:#f0f0f1e6;padding:10px 0;border-top:1px solid #c3c4c7;z-index:5}
</style>
<script>
(function(){
  document.querySelectorAll('.tom-tabs button').forEach(function(b){
    b.addEventListener('click',function(){
      document.querySelectorAll('.tom-tabs button').forEach(function(x){x.setAttribute('aria-selected',x===b?'true':'false')});
      document.querySelectorAll('.tom-tab').forEach(function(p){p.hidden=p.dataset.pane!==b.dataset.tab});
    });
  });
  document.querySelectorAll('.tom-copy').forEach(function(b){
    b.addEventListener('click',function(){
      var t=b.parentNode.querySelector('pre').textContent;
      navigator.clipboard.writeText(t).then(function(){b.textContent='Kopyalandı';setTimeout(function(){b.textContent='Kopyala'},1500)});
    });
  });
  var p=document.getElementById('tom-preset');
  if(p)p.addEventListener('change',function(){
    var o=p.selectedOptions[0]; if(!o||!o.dataset.lat)return;
    document.getElementById('tom-lat').value=o.dataset.lat; document.getElementById('tom-lon').value=o.dataset.lon; document.getElementById('tom-name').value=o.textContent;
  });
})();
</script>
    <?php
}
