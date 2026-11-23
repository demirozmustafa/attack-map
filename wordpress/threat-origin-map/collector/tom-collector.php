<?php
/**
 * Threat Origin Map — syslog collector (CLI only). Run by systemd; see WP Admin → Saldırı Haritası → Cihaz bağlama.
 *
 *   php tom-collector.php [--wp=/path/to/wordpress]
 *
 * Listens on UDP (port from the plugin settings), optionally tails Suricata eve.json,
 * batches lines once a second and writes them through the plugin's normal ingest pipeline.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
define('TOM_CLI', true);

$opts = getopt('', ['wp:']);
$root = $opts['wp'] ?? dirname(__DIR__, 4); // wp-content/plugins/threat-origin-map/collector → WP root
if (!is_file("$root/wp-load.php")) {
    fwrite(STDERR, "wp-load.php bulunamadı: $root  (--wp=/wordpress/yolu verin)\n");
    exit(1);
}
$_SERVER['HTTP_HOST'] = $_SERVER['HTTP_HOST'] ?? 'localhost';
define('WP_USE_THEMES', false);
require "$root/wp-load.php";
if (!function_exists('tom_ingest_lines')) {
    fwrite(STDERR, "Threat Origin Map eklentisi etkin değil. WordPress yönetim panelinden etkinleştirin.\n");
    exit(1);
}
@ini_set('memory_limit', '256M');
set_time_limit(0);

function tom_log($m) {
    fwrite(STDOUT, '[' . gmdate('H:i:s') . "] $m\n");
}

/** Re-read options written by the admin page (WP caches them per process). */
function tom_refresh() {
    wp_cache_flush();
    global $wpdb;
    if (method_exists($wpdb, 'check_connection')) {
        $wpdb->check_connection(false);
    }
    return tom_settings();
}

$running = true;
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, function () use (&$running) { $running = false; });
    pcntl_signal(SIGINT, function () use (&$running) { $running = false; });
}

$s = tom_refresh();
$sock = null;
$port = 0;
$eve = ['path' => '', 'fh' => null, 'ino' => null];
$batches = []; // sender => lines
$rejected = []; // sender => count
$last_flush = microtime(true);
$last_refresh = microtime(true);
$last_beat = 0;
$last_cleanup = 0;

function tom_bind($port) {
    $sock = @stream_socket_server("udp://0.0.0.0:$port", $errno, $errstr, STREAM_SERVER_BIND);
    if (!$sock) {
        tom_log("UDP $port açılamadı: $errstr");
        return null;
    }
    tom_log("Syslog UDP $port dinleniyor");
    return $sock;
}

function tom_eve_poll(array &$eve, $want, array &$batches) {
    if ($want !== $eve['path']) {
        if ($eve['fh']) {
            fclose($eve['fh']);
        }
        $eve = ['path' => $want, 'fh' => null, 'ino' => null, 'first' => true];
        if ($want) {
            tom_log("Suricata EVE izleniyor: $want");
        }
    }
    if (!$eve['path']) {
        return;
    }
    clearstatcache(true, $eve['path']);
    $st = @stat($eve['path']);
    if (!$st) {
        return;
    }
    if (!$eve['fh'] || $st['ino'] !== $eve['ino'] || $st['size'] < ftell($eve['fh'])) { // first open, rotated or truncated
        if ($eve['fh']) {
            fclose($eve['fh']);
        }
        $eve['fh'] = @fopen($eve['path'], 'rb');
        $eve['ino'] = $st['ino'];
        if (!$eve['fh']) {
            return;
        }
        if (!empty($eve['first'])) {
            fseek($eve['fh'], 0, SEEK_END); // don't replay history on start
            $eve['first'] = false;
        }
    }
    fseek($eve['fh'], ftell($eve['fh'])); // clears PHP's sticky EOF flag so newly appended lines are seen
    for ($i = 0; $i < 5000 && ($line = fgets($eve['fh'], 65536)) !== false; $i++) {
        if (substr($line, -1) !== "\n") { // partial line still being written
            fseek($eve['fh'], -strlen($line), SEEK_CUR);
            break;
        }
        $batches['eve.json'][] = $line;
    }
}

while ($running) {
    if ((int) $s['syslog_port'] !== $port || !$sock) {
        if ($sock) {
            fclose($sock);
        }
        $port = (int) $s['syslog_port'];
        $sock = tom_bind($port);
        if (!$sock) {
            sleep(5);
            $s = tom_refresh();
            continue;
        }
    }
    $r = [$sock];
    $w = $e = null;
    $n = @stream_select($r, $w, $e, 0, 250000);
    if ($n) {
        for ($i = 0; $i < 2000; $i++) { // drain what is queued without blocking
            $data = @stream_socket_recvfrom($sock, 65535, 0, $peer);
            if ($data === false || $data === '') {
                break;
            }
            $addr = $peer;
            if (preg_match('/^\[?([^\]]+?)\]?:\d+$/', $peer, $m)) {
                $addr = $m[1];
            }
            if (!tom_sender_allowed($addr, $s)) {
                $rejected[$addr] = ($rejected[$addr] ?? 0) + 1;
            } else {
                foreach (preg_split('/\r?\n/', $data) as $line) {
                    $batches[$addr][] = $line;
                }
            }
            $r = [$sock];
            if (!@stream_select($r, $w, $e, 0, 0)) {
                break;
            }
        }
    }

    $now = microtime(true);
    if ($now - $last_flush >= 1.0) {
        $last_flush = $now;
        if ($now - $last_refresh >= 5) {
            $last_refresh = $now;
            $s = tom_refresh();
        }
        tom_eve_poll($eve, !empty($s['sources']['suricata']) ? (string) $s['eve_file'] : '', $batches);
        foreach ($batches as $sender => $lines) {
            try {
                tom_ingest_lines($lines, (string) $sender);
            } catch (Throwable $ex) { // one bad batch must never stop the collector
                tom_log('Hata: ' . $ex->getMessage());
            }
        }
        foreach ($rejected as $addr => $cnt) {
            tom_status_add(['rejected' => $cnt], (string) $addr, false);
        }
        $batches = $rejected = [];
        if ($now - $last_cleanup >= 600) { // keeps the tables bounded even when WP-Cron never runs
            $last_cleanup = $now;
            try {
                tom_cleanup();
            } catch (Throwable $ex) {
                tom_log('Temizlik hatası: ' . $ex->getMessage());
            }
        }
        if ($now - $last_beat >= 10) {
            $last_beat = $now;
            update_option('tom_collector', ['last' => time(), 'port' => $port, 'pid' => getmypid(), 'eve' => $eve['path']], false);
        }
    }
}
tom_log('Durduruldu.');
