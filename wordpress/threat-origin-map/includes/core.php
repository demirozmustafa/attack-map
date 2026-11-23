<?php
/**
 * Core: settings, log parsers, classification, GeoIP, ingest pipeline, live stats.
 * Shared by the REST API (web requests) and the CLI syslog collector.
 */
defined('ABSPATH') || exit;

const TOM_TYPES = ['brute', 'web', 'scan', 'ddos', 'c2'];
const TOM_SOURCES = ['filterlog', 'suricata', 'fortigate'];
const TOM_DB_VERSION = 1;

/* ------------------------------------------------------------------ settings */

function tom_defaults() {
    return [
        'site_name' => 'İstanbul',
        'lat' => 41.01,
        'lon' => 28.98,
        'title' => 'Where attackers come from',
        'allowed_senders' => '',
        'sources' => ['filterlog' => 1, 'suricata' => 1, 'fortigate' => 1],
        'eve_file' => '',
        'syslog_port' => 5514,
        'max_eps' => 40,
        'public' => 1,
        'mask_ips' => 1,
        'demo' => 0,
        'retention_days' => 7,
        'ingest_token' => '',
        'geo_account' => '',
        'geo_key' => '',
        'geo_auto' => 1,
    ];
}

function tom_settings() {
    $s = get_option('tom_settings');
    $s = is_array($s) ? $s : [];
    $d = tom_defaults();
    $s = array_merge($d, $s);
    $s['sources'] = array_merge($d['sources'], is_array($s['sources']) ? $s['sources'] : []);
    return $s;
}

function tom_update_settings(array $patch) {
    update_option('tom_settings', array_merge(tom_settings(), $patch), false);
}

/** Uploads subfolder that holds the GeoIP database. Web-unguessable file names are used inside. */
function tom_data_dir() {
    $u = wp_upload_dir(null, false);
    $dir = trailingslashit($u['basedir']) . 'threat-origin-map';
    if (!is_dir($dir)) {
        wp_mkdir_p($dir);
        @file_put_contents($dir . '/index.php', "<?php // Silence.\n");
        @file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
    }
    return $dir;
}

/** wp_tempnam() lives in an admin-only file; cron and the CLI collector need it too. */
function tom_tempnam($name) {
    if (!function_exists('wp_tempnam')) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }
    return wp_tempnam($name);
}

/* ------------------------------------------------------------------ tables */

function tom_tables() {
    global $wpdb;
    return [
        'events' => $wpdb->prefix . 'tom_events',
        'counts' => $wpdb->prefix . 'tom_counts',
        'ips' => $wpdb->prefix . 'tom_ips',
    ];
}

function tom_install_tables() {
    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $t = tom_tables();
    $cs = $wpdb->get_charset_collate();
    dbDelta("CREATE TABLE {$t['events']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  ts bigint(20) unsigned NOT NULL,
  ip varchar(45) NOT NULL,
  cc char(2) NOT NULL,
  country varchar(64) NOT NULL,
  lat float NOT NULL,
  lon float NOT NULL,
  type varchar(8) NOT NULL,
  port int(11) DEFAULT NULL,
  proto varchar(8) NOT NULL DEFAULT '',
  detail varchar(160) NOT NULL DEFAULT '',
  sensor varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY  (id),
  KEY ts (ts)
) $cs;");
    dbDelta("CREATE TABLE {$t['counts']} (
  minute int(10) unsigned NOT NULL,
  cc char(2) NOT NULL,
  type varchar(8) NOT NULL,
  country varchar(64) NOT NULL DEFAULT '',
  n int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (minute,cc,type)
) $cs;");
    dbDelta("CREATE TABLE {$t['ips']} (
  day int(10) unsigned NOT NULL,
  ip varchar(45) NOT NULL,
  PRIMARY KEY  (day,ip)
) $cs;");
    update_option('tom_db_version', TOM_DB_VERSION, true);
}

/* ------------------------------------------------------------------ classification + parsers */

function tom_classify($port, $proto, $text = '') {
    static $kw = [
        'c2' => '/trojan|malware|command and control|\bc2\b|\bcnc\b|botnet|virus|ransom/i',
        'ddos' => '/denial of service|\bd?dos\b|flood|anomaly/i',
        'brute' => '/brute|ssh|rdp|telnet|login|password|auth/i',
        'web' => '/web application|sql|xss|http|php|wordpress|apache|nginx|waf|log4j|struts/i',
        'scan' => '/scan|recon|probe|nmap|masscan|zgrab/i',
    ];
    if ($text !== '') {
        foreach ($kw as $k => $rx) {
            if (preg_match($rx, $text)) {
                return $k;
            }
        }
    }
    if (in_array($port, [21, 22, 23, 25, 110, 143, 445, 1433, 2222, 3306, 3389, 5432, 5900], true)) {
        return 'brute';
    }
    if (in_array($port, [80, 443, 8000, 8080, 8443, 8888], true)) {
        return 'web';
    }
    if ($proto === 'udp' && in_array($port, [19, 53, 123, 161, 389, 1900, 11211], true)) {
        return 'ddos';
    }
    return 'scan';
}

function tom_int($v) {
    if (is_int($v)) {
        return $v;
    }
    if (is_string($v) && preg_match('/^\d{1,9}$/', $v)) {
        return (int) $v;
    }
    return null;
}

/** pfSense / OPNsense filterlog CSV. Keeps inbound blocks only. */
function tom_parse_filterlog($msg) {
    if (!preg_match('/filterlog.*?[\s:](\d+,\S+)/', $msg, $m)) {
        return null;
    }
    $f = explode(',', $m[1]);
    if (count($f) < 10 || $f[6] !== 'block' || $f[7] !== 'in') {
        return null;
    }
    if ($f[8] === '4' && count($f) >= 20) {
        [$proto, $src, $rest] = [strtolower($f[16]), $f[18], array_slice($f, 20)];
    } elseif ($f[8] === '6' && count($f) >= 17) {
        [$proto, $src, $rest] = [strtolower($f[12]), $f[15], array_slice($f, 17)];
    } else {
        return null;
    }
    $port = (in_array($proto, ['tcp', 'udp'], true) && count($rest) >= 2) ? tom_int($rest[1]) : null;
    return ['src' => $src, 'port' => $port, 'proto' => $proto, 'detail' => 'Blocked on ' . $f[4], 'sensor' => 'firewall', 'text' => ''];
}

/** Suricata EVE alert (decoded JSON). */
function tom_parse_eve($o) {
    if (!is_array($o) || ($o['event_type'] ?? '') !== 'alert') {
        return null;
    }
    $a = is_array($o['alert'] ?? null) ? $o['alert'] : [];
    $sig = (string) ($a['signature'] ?? '');
    $cat = (string) ($a['category'] ?? '');
    return [
        'src' => (string) ($o['src_ip'] ?? ''),
        'port' => tom_int($o['dest_port'] ?? null),
        'proto' => strtolower((string) ($o['proto'] ?? '')),
        'detail' => $sig ?: ($cat ?: 'IDS alert'),
        'sensor' => 'ids',
        'text' => "$cat $sig",
    ];
}

/** FortiGate key=value log. */
function tom_parse_forti($msg) {
    preg_match_all('/(\w+)=(?:"([^"]*)"|(\S+))/', $msg, $mm, PREG_SET_ORDER);
    $kv = [];
    foreach ($mm as $m) {
        $kv[$m[1]] = isset($m[3]) && $m[3] !== '' ? $m[3] : $m[2];
    }
    if (!isset($kv['srcip'])) {
        return null;
    }
    $sub = strtolower($kv['subtype'] ?? '');
    $action = strtolower($kv['action'] ?? '');
    $block = ['deny', 'blocked', 'block', 'dropped', 'drop', 'reset', 'clear_session', 'server-rst', 'client-rst'];
    if (!in_array($sub, ['ips', 'anomaly', 'waf', 'virus', 'webfilter'], true) && !in_array($action, $block, true)) {
        return null;
    }
    $text = implode(' ', array_filter([$kv['attack'] ?? '', $kv['msg'] ?? '', $kv['catdesc'] ?? '', $sub === 'anomaly' ? 'anomaly' : '']));
    $detail = ($kv['attack'] ?? '') ?: (($kv['msg'] ?? '') ?: trim(($action ?: $sub) . ' ' . ($kv['policyname'] ?? '')));
    $p = $kv['proto'] ?? '';
    return [
        'src' => $kv['srcip'],
        'port' => tom_int($kv['dstport'] ?? null),
        'proto' => ['6' => 'tcp', '17' => 'udp', '1' => 'icmp'][$p] ?? strtolower($p),
        'detail' => $detail,
        'sensor' => 'fortigate',
        'text' => $text,
    ];
}

function tom_parse_line($msg, $sources = null) {
    $on = $sources ?: array_fill_keys(TOM_SOURCES, 1);
    if (strpos($msg, '"event_type"') !== false) {
        if (empty($on['suricata'])) {
            return null;
        }
        $i = strpos($msg, '{');
        if ($i !== false) {
            $o = json_decode(substr($msg, $i), true);
            return is_array($o) ? tom_parse_eve($o) : null;
        }
    }
    if (strpos($msg, 'filterlog') !== false) {
        return empty($on['filterlog']) ? null : tom_parse_filterlog($msg);
    }
    if (strpos($msg, 'srcip=') !== false) {
        return empty($on['fortigate']) ? null : tom_parse_forti($msg);
    }
    return null;
}

/** True for globally routable addresses (drops private, loopback, CGNAT, documentation, reserved). */
function tom_is_public_ip($ip) {
    $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
    if (defined('FILTER_FLAG_GLOBAL_RANGE')) {
        $flags |= FILTER_FLAG_GLOBAL_RANGE;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, $flags)) {
        return false;
    }
    $nets = ['100.64.0.0/10', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'];
    foreach ($nets as $n) {
        if (tom_ip_in_cidr($ip, $n)) {
            return false;
        }
    }
    return true;
}

function tom_ip_in_cidr($ip, $cidr) {
    $parts = explode('/', $cidr, 2);
    $net = @inet_pton($parts[0]);
    $addr = @inet_pton($ip);
    if ($net === false || $addr === false || strlen($net) !== strlen($addr)) {
        return false;
    }
    $bits = isset($parts[1]) ? (int) $parts[1] : strlen($net) * 8;
    $bytes = intdiv($bits, 8);
    if (substr($net, 0, $bytes) !== substr($addr, 0, $bytes)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($net[$bytes]) & $mask) === (ord($addr[$bytes]) & $mask);
}

/** Empty allow list = accept any sender (the CloudPanel/cloud firewall should still restrict the port). */
function tom_sender_allowed($addr, $list) {
    $list = trim((string) $list);
    if ($list === '') {
        return true;
    }
    foreach (preg_split('/[\s,]+/', $list) as $entry) {
        if ($entry !== '' && tom_ip_in_cidr($addr, $entry)) {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ GeoIP */

const TOM_GEO_URL = 'https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz';

/** @return TOM_MMDB|null */
function tom_geo_reader() {
    static $reader = false, $loaded_file = null;
    $file = get_option('tom_geo_file');
    if ($reader !== false && $loaded_file === $file) {
        return $reader;
    }
    $reader = null;
    $loaded_file = $file;
    if ($file) {
        $path = tom_data_dir() . '/' . basename($file);
        if (is_file($path)) {
            try {
                $reader = new TOM_MMDB($path);
            } catch (Exception $e) {
                $reader = null;
            }
        }
    }
    return $reader;
}

function tom_geo_lookup($ip) {
    static $cache = [], $for = null;
    $r = tom_geo_reader();
    if ($for !== $r) { // database replaced: forget old answers
        $cache = [];
        $for = $r;
    }
    if (array_key_exists($ip, $cache)) {
        return $cache[$ip];
    }
    $out = null;
    if ($r) {
        try {
            $rec = $r->get($ip);
        } catch (Exception $e) {
            $rec = null;
        }
        if (is_array($rec)) {
            $loc = $rec['location'] ?? [];
            $c = $rec['country'] ?? ($rec['registered_country'] ?? []);
            if (isset($loc['latitude'], $loc['longitude']) && !empty($c['iso_code'])) {
                $out = [
                    'lat' => round($loc['latitude'], 2),
                    'lon' => round($loc['longitude'], 2),
                    'cc' => substr($c['iso_code'], 0, 2),
                    'country' => substr($c['names']['en'] ?? $c['iso_code'], 0, 64),
                ];
            }
        }
    }
    if (count($cache) > 50000) {
        $cache = [];
    }
    return $cache[$ip] = $out;
}

/** Validate a .mmdb file on disk and make it the active database. Throws on failure. */
function tom_geo_install($tmp_path) {
    try {
        $r = new TOM_MMDB($tmp_path);
    } catch (Exception $e) {
        throw new Exception('Geçerli bir MaxMind .mmdb dosyası değil.');
    }
    $type = (string) ($r->metadata['database_type'] ?? '');
    $built = (int) ($r->metadata['build_epoch'] ?? 0);
    unset($r);
    if (strpos($type, 'City') === false) {
        throw new Exception('Bu bir City veritabanı değil. GeoLite2-City (.mmdb) gerekli; Country sürümünde konum yok.');
    }
    $dir = tom_data_dir();
    $name = 'geo-' . time() . '-' . wp_generate_password(16, false) . '.mmdb';
    if (!@rename($tmp_path, "$dir/$name") && !@copy($tmp_path, "$dir/$name")) {
        throw new Exception('Veritabanı uploads klasörüne yazılamadı.');
    }
    @chmod("$dir/$name", 0644);
    $old = get_option('tom_geo_file');
    update_option('tom_geo_file', $name, true);
    update_option('tom_geo_meta', ['type' => $type, 'built' => $built ? gmdate('Y-m-d', $built) : '', 'updated' => time(), 'error' => ''], false);
    if ($old && $old !== $name) {
        @unlink("$dir/" . basename($old));
    }
}

/** Download GeoLite2-City from MaxMind (streams to disk, extracts the .mmdb from the tar.gz). Throws on failure. */
function tom_geo_download() {
    $s = tom_settings();
    if (!$s['geo_account'] || !$s['geo_key']) {
        throw new Exception('Önce MaxMind Account ID ve License Key girin.');
    }
    @set_time_limit(600);
    $tgz = tom_tempnam('geolite2.tar.gz');
    $args = [
        'timeout' => 30,
        'redirection' => 0, // follow by hand: the credentials must not reach the storage host
        'headers' => ['Authorization' => 'Basic ' . base64_encode($s['geo_account'] . ':' . $s['geo_key'])],
        'user-agent' => 'threat-origin-map/' . TOM_VERSION,
    ];
    $res = wp_remote_get(TOM_GEO_URL, $args);
    if (is_wp_error($res)) {
        throw new Exception('MaxMind\'a bağlanılamadı: ' . $res->get_error_message());
    }
    $code = wp_remote_retrieve_response_code($res);
    if (in_array($code, [401, 403], true)) {
        throw new Exception('Account ID veya License Key hatalı.');
    }
    $loc = wp_remote_retrieve_header($res, 'location');
    $dl_args = ['timeout' => 300, 'stream' => true, 'filename' => $tgz, 'user-agent' => $args['user-agent']];
    if ($code >= 300 && $code < 400 && $loc) {
        $res = wp_remote_get($loc, $dl_args);
    } elseif ($code === 200) {
        $res = wp_remote_get(TOM_GEO_URL, $dl_args + ['headers' => $args['headers']]);
    } else {
        @unlink($tgz);
        throw new Exception('MaxMind HTTP ' . $code);
    }
    if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) {
        @unlink($tgz);
        throw new Exception('İndirme başarısız: ' . (is_wp_error($res) ? $res->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($res)));
    }
    $mmdb = tom_tempnam('geolite2.mmdb');
    try {
        tom_untar_member($tgz, '.mmdb', $mmdb);
        tom_geo_install($mmdb);
    } finally {
        @unlink($tgz);
        @unlink($mmdb);
    }
}

/** Streams the first file ending in $suffix out of a .tar.gz into $dest. No Phar needed. */
function tom_untar_member($tgz, $suffix, $dest) {
    $gz = gzopen($tgz, 'rb');
    if (!$gz) {
        throw new Exception('Arşiv açılamadı.');
    }
    try {
        while (!gzeof($gz)) {
            $h = gzread($gz, 512);
            if (strlen($h) < 512 || trim($h, "\0") === '') {
                break;
            }
            $name = rtrim(substr($h, 0, 100), "\0");
            $prefix = rtrim(substr($h, 345, 155), "\0");
            if (substr($h, 257, 5) === 'ustar' && $prefix !== '') {
                $name = $prefix . '/' . $name;
            }
            $size = octdec(trim(substr($h, 124, 12), " \0"));
            $flag = $h[156];
            $padded = (int) (ceil($size / 512) * 512);
            if (($flag === '0' || $flag === "\0") && substr($name, -strlen($suffix)) === $suffix) {
                $out = fopen($dest, 'wb');
                $left = $size;
                while ($left > 0) {
                    $chunk = gzread($gz, (int) min(1 << 20, $left));
                    if ($chunk === false || $chunk === '') {
                        throw new Exception('Arşiv eksik.');
                    }
                    fwrite($out, $chunk);
                    $left -= strlen($chunk);
                }
                fclose($out);
                return;
            }
            for ($skip = $padded; $skip > 0;) { // gzseek is slow/unsupported in some builds; read through
                $chunk = gzread($gz, (int) min(1 << 20, $skip));
                if ($chunk === false || $chunk === '') {
                    break 2;
                }
                $skip -= strlen($chunk);
            }
            continue;
        }
    } finally {
        gzclose($gz);
    }
    throw new Exception('Arşivde .mmdb bulunamadı.');
}

/* ------------------------------------------------------------------ ingest */

/** Adds raw log lines from one sender. Returns counters. */
function tom_ingest_lines(array $lines, $sender, $sensor_label = '') {
    $s = tom_settings();
    $c = ['received' => 0, 'parsed' => 0, 'ignored' => 0];
    $recs = [];
    foreach ($lines as $line) {
        $line = trim((string) $line);
        if ($line === '') {
            continue;
        }
        $c['received']++;
        $rec = tom_parse_line(substr($line, 0, 16384), $s['sources']);
        if ($rec) {
            $c['parsed']++;
            if ($sensor_label !== '') {
                $rec['sensor'] = $sensor_label;
            }
            $recs[] = $rec;
        } else {
            $c['ignored']++;
        }
    }
    $c += tom_ingest_records($recs);
    tom_status_add($c, $sender);
    return $c;
}

/**
 * Geolocates + classifies parsed records and stores them:
 * every event counts towards the totals; only up to max_eps per second are stored for drawing.
 */
function tom_ingest_records(array $recs, $geo_override = null) {
    global $wpdb;
    $out = ['private' => 0, 'unlocated' => 0, 'stored' => 0];
    if (!$recs) {
        return $out;
    }
    $s = tom_settings();
    $t = tom_tables();
    $now = microtime(true);
    $minute = (int) floor($now / 60);
    $day = (int) wp_date('Ymd', (int) $now);
    $counts = [];
    $ips = [];
    $events = [];
    $located = [];
    foreach ($recs as $i => $rec) {
        $ip = trim((string) ($rec['src'] ?? ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }
        $ip = inet_ntop(inet_pton($ip));
        if (!$geo_override && !tom_is_public_ip($ip)) {
            $out['private']++;
            continue;
        }
        $g = $geo_override ? (is_array($geo_override) && isset($geo_override[$i]) ? $geo_override[$i] : null) : tom_geo_lookup($ip);
        if (!$g) {
            $out['unlocated']++;
            continue;
        }
        $type = tom_classify($rec['port'] ?? null, (string) ($rec['proto'] ?? ''), (string) ($rec['text'] ?? ''));
        $k = "{$g['cc']}|$type";
        if (!isset($counts[$k])) {
            $counts[$k] = [$g['cc'], $type, $g['country'], 0];
        }
        $counts[$k][3]++;
        $ips[$ip] = 1;
        $located[] = [$rec, $ip, $g, $type];
    }
    $budget = $located ? tom_take_tokens(count($located), (float) $s['max_eps']) : 0;
    if ($budget < count($located)) {
        update_option('tom_sampled_at', time(), false);
        // keep an even sample across the batch rather than only its first rows
        $step = count($located) / max(1, $budget);
        $picked = [];
        for ($j = 0; $j < $budget; $j++) {
            $picked[] = $located[(int) floor($j * $step)];
        }
        $located = $picked;
    }
    foreach ($located as [$rec, $ip, $g, $type]) {
        $events[] = [
            (int) round(($rec['ts'] ?? $now) * 1000), $ip, $g['cc'], $g['country'], $g['lat'], $g['lon'], $type,
            $rec['port'] ?? null, substr((string) ($rec['proto'] ?? ''), 0, 8),
            mb_substr(wp_check_invalid_utf8((string) ($rec['detail'] ?? '')), 0, 160),
            substr((string) ($rec['sensor'] ?? ''), 0, 32),
        ];
    }
    foreach (array_chunk(array_values($counts), 200) as $chunk) {
        $vals = [];
        foreach ($chunk as [$cc, $type, $country, $n]) {
            $vals[] = $wpdb->prepare('(%d,%s,%s,%s,%d)', $minute, $cc, $type, $country, $n);
        }
        $wpdb->query("INSERT INTO {$t['counts']} (minute,cc,type,country,n) VALUES " . implode(',', $vals)
            . ' ON DUPLICATE KEY UPDATE n=n+VALUES(n), country=VALUES(country)');
    }
    foreach (array_chunk(array_keys($ips), 500) as $chunk) {
        $vals = [];
        foreach ($chunk as $ip) {
            $vals[] = $wpdb->prepare('(%d,%s)', $day, $ip);
        }
        $wpdb->query("INSERT IGNORE INTO {$t['ips']} (day,ip) VALUES " . implode(',', $vals));
    }
    foreach (array_chunk($events, 200) as $chunk) {
        $vals = [];
        foreach ($chunk as $e) {
            $port = $e[7] === null ? 'NULL' : (string) (int) $e[7];
            $vals[] = $wpdb->prepare('(%d,%s,%s,%s,%f,%f,%s,', $e[0], $e[1], $e[2], $e[3], $e[4], $e[5], $e[6])
                . $port . $wpdb->prepare(',%s,%s,%s)', $e[8], $e[9], $e[10]);
        }
        $wpdb->query("INSERT INTO {$t['events']} (ts,ip,cc,country,lat,lon,type,port,proto,detail,sensor) VALUES " . implode(',', $vals));
    }
    $out['stored'] = count($events);
    if ($counts) {
        wp_cache_delete('tom_stats', 'tom');
    }
    return $out;
}

/** Token bucket shared by all writers (collector + REST). Returns how many events may be stored now. */
function tom_take_tokens($want, $rate) {
    $rate = max(1.0, $rate);
    $b = get_option('tom_bucket');
    $now = microtime(true);
    $tokens = is_array($b) ? min($rate, $b[0] + ($now - $b[1]) * $rate) : $rate;
    $take = (int) min($want, floor($tokens));
    update_option('tom_bucket', [$tokens - $take, $now], false);
    return $take;
}

/** Status counters + recently seen senders (for the admin page). */
function tom_status_add(array $c, $sender, $allowed = true) {
    $st = get_option('tom_status');
    $st = is_array($st) ? $st : ['since' => time(), 'senders' => []];
    foreach (['received', 'parsed', 'ignored', 'private', 'unlocated', 'rejected'] as $k) {
        $st[$k] = ($st[$k] ?? 0) + ($c[$k] ?? 0);
    }
    if ($sender !== '') {
        $x = $st['senders'][$sender] ?? ['count' => 0, 'parsed' => 0];
        $x['count'] += ($c['received'] ?? 0) + ($c['rejected'] ?? 0);
        $x['parsed'] += $c['parsed'] ?? 0;
        $x['last'] = time();
        $x['allowed'] = $allowed;
        $st['senders'][$sender] = $x;
        if (count($st['senders']) > 50) {
            uasort($st['senders'], function ($a, $b) { return $b['last'] <=> $a['last']; });
            $st['senders'] = array_slice($st['senders'], 0, 50, true);
        }
    }
    update_option('tom_status', $st, false);
}

/* ------------------------------------------------------------------ demo + test events */

function tom_synthetic_lines($n) {
    $sigs = [
        ['ET SCAN Potential SSH Scan', 'Attempted Information Leak', 22],
        ['ET WEB_SERVER Possible SQL Injection Attempt', 'Web Application Attack', 443],
        ['ET MALWARE Possible Mirai Botnet C2 Traffic', 'A Network Trojan was detected', 23],
        ['ET DOS Possible NTP DDoS Inbound', 'Attempted Denial of Service', 123],
    ];
    $firsts = [45, 61, 80, 103, 112, 176, 185, 193, 194, 222];
    $lines = [];
    for ($i = 0; $i < $n; $i++) {
        $src = $firsts[array_rand($firsts)] . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(1, 254);
        $k = mt_rand() / mt_getrandmax();
        if ($k < 0.55) {
            $ports = [22, 22, 3389, 443, 80, 23, 445, 8080, 5060, 1433, 6379, 53, 123];
            $port = $ports[array_rand($ports)];
            $proto = in_array($port, [53, 123, 5060], true) ? 'udp' : 'tcp';
            $pid = $proto === 'udp' ? '17' : '6';
            $lines[] = "filterlog[1]: 5,,,1000000103,wan,match,block,in,4,0x0,,52,0,0,DF,$pid,$proto,60,$src,203.0.113.10," . mt_rand(1024, 65000) . ",$port,0,S,1,,64240,,mss";
        } elseif ($k < 0.85) {
            [$sig, $cat, $port] = $sigs[array_rand($sigs)];
            $lines[] = 'suricata[42]: ' . wp_json_encode(['event_type' => 'alert', 'src_ip' => $src, 'dest_ip' => '203.0.113.10', 'dest_port' => $port,
                'proto' => $port === 123 ? 'UDP' : 'TCP', 'alert' => ['signature' => $sig, 'category' => $cat, 'severity' => 2]]);
        } else {
            $lines[] = "type=\"utm\" subtype=\"ips\" action=\"dropped\" srcip=$src dstip=203.0.113.10 dstport=80 proto=6 attack=\"Apache.Log4j.Error.Log.Remote.Code.Execution\"";
        }
    }
    return $lines;
}

function tom_synthetic_geo() {
    static $geo = [
        ['CN', 'China', 31.23, 121.47, 18], ['US', 'United States', 37.75, -97.82, 12], ['RU', 'Russia', 55.75, 37.62, 11],
        ['BR', 'Brazil', -23.55, -46.63, 7], ['IN', 'India', 19.08, 72.88, 7], ['VN', 'Vietnam', 21.03, 105.85, 6],
        ['NL', 'Netherlands', 52.37, 4.89, 6], ['DE', 'Germany', 50.11, 8.68, 4], ['IR', 'Iran', 35.69, 51.39, 4],
        ['KR', 'South Korea', 37.57, 126.98, 4], ['ID', 'Indonesia', -6.21, 106.85, 4], ['SG', 'Singapore', 1.35, 103.82, 3],
        ['RO', 'Romania', 44.43, 26.1, 3], ['UA', 'Ukraine', 50.45, 30.52, 3], ['FR', 'France', 48.86, 2.35, 2],
    ];
    $total = array_sum(array_column($geo, 4));
    $r = mt_rand(1, $total);
    foreach ($geo as [$cc, $name, $lat, $lon, $w]) {
        if (($r -= $w) <= 0) {
            break;
        }
    }
    return ['cc' => $cc, 'country' => $name, 'lat' => round($lat + mt_rand(-300, 300) / 100, 2), 'lon' => round($lon + mt_rand(-300, 300) / 100, 2)];
}

/** Runs synthetic lines through the real parsers, with made-up locations and spread-out timestamps. */
function tom_inject_synthetic($n, $sensor, $span_s = 0.0) {
    $recs = [];
    $geo = [];
    $now = microtime(true);
    foreach (tom_synthetic_lines($n) as $i => $line) {
        $rec = tom_parse_line($line);
        if (!$rec) {
            continue;
        }
        $rec['sensor'] = $sensor;
        $rec['ts'] = $now - $span_s + ($n > 1 ? $span_s * $i / ($n - 1) : $span_s);
        $geo[count($recs)] = tom_synthetic_geo();
        $recs[] = $rec;
    }
    return tom_ingest_records($recs, $geo);
}

/** Demo mode has no background worker on shared PHP: viewers' polls top it up based on elapsed time. */
function tom_demo_tick() {
    $last = (float) get_option('tom_demo_last', 0);
    $now = microtime(true);
    $gap = $now - $last;
    if ($gap < 1.5) {
        return;
    }
    update_option('tom_demo_last', $now, false);
    $gap = min($gap, 4.0);
    $n = max(1, (int) round($gap * (3 + mt_rand(0, 40) / 10)));
    tom_inject_synthetic($n, 'demo', $gap);
}

/* ------------------------------------------------------------------ reading */

function tom_stats() {
    global $wpdb;
    $cached = wp_cache_get('tom_stats', 'tom');
    if ($cached !== false) {
        return $cached;
    }
    $t = tom_tables();
    $now_min = (int) floor(time() / 60);
    $midnight = (int) floor((new DateTime('today', wp_timezone()))->getTimestamp() / 60);
    $day = (int) wp_date('Ymd');
    $from = $now_min - 14;
    $top = $wpdb->get_results($wpdb->prepare(
        "SELECT cc, MAX(country) AS country, SUM(n) AS n FROM {$t['counts']} WHERE minute >= %d GROUP BY cc ORDER BY n DESC LIMIT 7", $from), ARRAY_A);
    $types = array_fill_keys(TOM_TYPES, 0);
    foreach ($wpdb->get_results($wpdb->prepare("SELECT type, SUM(n) AS n FROM {$t['counts']} WHERE minute >= %d GROUP BY type", $from), ARRAY_A) as $r) {
        if (isset($types[$r['type']])) {
            $types[$r['type']] = (int) $r['n'];
        }
    }
    $today = $wpdb->get_row($wpdb->prepare(
        "SELECT COALESCE(SUM(n),0) AS total, COUNT(DISTINCT cc) AS countries FROM {$t['counts']} WHERE minute >= %d", $midnight), ARRAY_A);
    $per_min = (int) $wpdb->get_var($wpdb->prepare("SELECT COALESCE(SUM(n),0) FROM {$t['counts']} WHERE minute = %d", $now_min - 1));
    $s = tom_settings();
    $stats = [
        'total_today' => (int) $today['total'],
        'unique_ips' => (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$t['ips']} WHERE day = %d", $day)),
        'countries' => (int) $today['countries'],
        'per_min' => $per_min,
        'last_15m' => array_sum($types),
        'top' => array_map(function ($r) { return [$r['cc'], $r['country'], (int) $r['n']]; }, $top ?: []),
        'types' => $types,
        'sampled' => (time() - (int) get_option('tom_sampled_at', 0)) < 900,
        'geoip_ready' => (bool) tom_geo_reader() || !empty($s['demo']),
        'demo' => !empty($s['demo']),
    ];
    wp_cache_set('tom_stats', $stats, 'tom', 2);
    return $stats;
}

function tom_mask_ip($ip) {
    if (strpos($ip, ':') !== false) {
        $p = explode(':', $ip);
        return implode(':', array_slice($p, 0, 3)) . ':…';
    }
    $p = explode('.', $ip);
    $p[3] = 'x';
    return implode('.', $p);
}

/** Events with id > $after (newest 150 at most), oldest first. */
function tom_events_after($after, $mask) {
    global $wpdb;
    $t = tom_tables();
    $min_ts = (int) ((time() - 3600) * 1000);
    $rows = $wpdb->get_results($wpdb->prepare(
        "SELECT id, ts, ip, cc, country, lat, lon, type, port, proto, detail, sensor FROM {$t['events']} WHERE id > %d AND ts >= %d ORDER BY id DESC LIMIT 150",
        $after, $min_ts), ARRAY_A) ?: [];
    $rows = array_reverse($rows);
    foreach ($rows as &$r) {
        $r['id'] = (int) $r['id'];
        $r['ts'] = (int) $r['ts'];
        $r['lat'] = (float) $r['lat'];
        $r['lon'] = (float) $r['lon'];
        $r['port'] = $r['port'] === null ? null : (int) $r['port'];
        if ($mask) {
            $r['ip'] = tom_mask_ip($r['ip']);
        }
    }
    return $rows;
}

/* ------------------------------------------------------------------ housekeeping */

function tom_cleanup() {
    global $wpdb;
    $t = tom_tables();
    $s = tom_settings();
    $keep = max(1, (int) $s['retention_days']);
    $wpdb->query($wpdb->prepare("DELETE FROM {$t['events']} WHERE ts < %d", (time() - $keep * 86400) * 1000));
    $wpdb->query($wpdb->prepare("DELETE FROM {$t['counts']} WHERE minute < %d", (int) floor(time() / 60) - max(2, $keep) * 1440));
    $wpdb->query($wpdb->prepare("DELETE FROM {$t['ips']} WHERE day < %d", (int) wp_date('Ymd', time() - 2 * 86400)));
}

function tom_geo_auto_update() {
    $s = tom_settings();
    if (empty($s['geo_auto']) || !$s['geo_account'] || !$s['geo_key']) {
        return;
    }
    $m = get_option('tom_geo_meta');
    if (is_array($m) && !empty($m['updated']) && time() - $m['updated'] < 6 * 86400 && tom_geo_reader()) {
        return;
    }
    try {
        tom_geo_download();
    } catch (Exception $e) {
        $m = is_array($m) ? $m : [];
        $m['error'] = $e->getMessage();
        update_option('tom_geo_meta', $m, false);
    }
}

function tom_collector_state() {
    $c = get_option('tom_collector');
    if (!is_array($c) || empty($c['last'])) {
        return ['running' => false, 'seen' => false];
    }
    return $c + ['running' => time() - $c['last'] < 30, 'seen' => true];
}
