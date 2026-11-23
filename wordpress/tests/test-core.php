<?php
/**
 * Plain-PHP tests for the parsers, classifier, IP filters and the .mmdb reader (no WordPress needed).
 *   php tests/test-core.php [path/to/GeoIP2-City-Test.mmdb]
 */
define('ABSPATH', __DIR__ . '/');
require __DIR__ . '/../threat-origin-map/includes/mmdb.php';
require __DIR__ . '/../threat-origin-map/includes/core.php';

$fail = 0;
function eq($got, $want, $name) {
    global $fail;
    if ($got === $want) {
        echo "ok   $name\n";
    } else {
        $fail++;
        echo "FAIL $name\n     got:  " . var_export($got, true) . "\n     want: " . var_export($want, true) . "\n";
    }
}
function pick($r, ...$k) { return $r ? array_map(function ($x) use ($r) { return $r[$x]; }, $k) : null; }

$PF_V4 = '<134>1 2026-11-19T12:00:00+03:00 fw.local filterlog 4321 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,49,54321,0,none,6,tcp,44,185.220.101.5,203.0.113.10,51515,22,0,S,1234567,,1024,,mss';
$PF_V6 = '<134>Nov 19 12:00:00 filterlog[555]: 7,,,1000000105,igb0,match,block,in,6,0x00,0x00000,57,udp,17,40,2a03:2880:f003:c07:face:b00c::2,2001:db8::1,40000,123,40';
$EVE = '<14>Nov 19 12:00:01 ids suricata[1234]: {"timestamp":"2026-11-19T12:00:01.000+0300","event_type":"alert","src_ip":"45.155.205.233","src_port":44211,"dest_ip":"203.0.113.10","dest_port":443,"proto":"TCP","alert":{"action":"allowed","signature_id":2011716,"signature":"ET WEB_SERVER Possible SQL Injection Attempt","category":"Web Application Attack","severity":1}}';
$FT = 'date=2026-11-19 time=12:00:02 devname="FG100F" type="traffic" subtype="forward" level="notice" srcip=91.240.118.172 srcport=55120 srcintf="wan1" dstip=203.0.113.10 dstport=3389 proto=6 action="deny" policyid=0 policytype="policy"';
$FT_IPS = 'date=2026-11-19 time=12:00:03 type="utm" subtype="ips" level="alert" srcip=193.42.33.7 dstip=203.0.113.10 dstport=80 proto=6 action="dropped" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" msg="web_server: Apache.Log4j"';

$r = tom_parse_line($PF_V4);
eq(pick($r, 'src', 'port', 'proto'), ['185.220.101.5', 22, 'tcp'], 'filterlog v4 block');
eq(tom_classify($r['port'], $r['proto'], $r['text']), 'brute', 'filterlog v4 → brute');
eq(tom_parse_line(str_replace(',block,in,', ',pass,in,', $PF_V4)), null, 'filterlog pass ignored');
eq(tom_parse_line(str_replace(',block,in,', ',block,out,', $PF_V4)), null, 'filterlog outbound ignored');
$r = tom_parse_line($PF_V6);
eq(pick($r, 'src', 'port', 'proto'), ['2a03:2880:f003:c07:face:b00c::2', 123, 'udp'], 'filterlog v6');
eq(tom_classify($r['port'], $r['proto'], $r['text']), 'ddos', 'filterlog v6 NTP → ddos');
$r = tom_parse_line($EVE);
eq(pick($r, 'src', 'port'), ['45.155.205.233', 443], 'eve alert');
eq(tom_classify($r['port'], $r['proto'], $r['text']), 'web', 'eve → web');
eq(tom_parse_line('<14>suricata[1]: {"event_type":"flow","src_ip":"45.155.205.233"}'), null, 'eve flow ignored');
$r = tom_parse_line($FT);
eq(pick($r, 'src', 'port', 'proto'), ['91.240.118.172', 3389, 'tcp'], 'fortigate deny');
eq(tom_classify($r['port'], $r['proto'], $r['text']), 'brute', 'fortigate → brute');
$r = tom_parse_line($FT_IPS);
eq(tom_classify($r['port'], $r['proto'], $r['text']), 'web', 'fortigate ips → web');
eq(tom_parse_line(str_replace('action="deny"', 'action="accept"', $FT)), null, 'fortigate accept ignored');
eq(tom_classify(23, 'tcp', 'A Network Trojan was detected ET MALWARE Mirai'), 'c2', 'keyword c2');
eq(tom_classify(5555, 'tcp', ''), 'scan', 'fallback scan');
eq(tom_parse_line($PF_V4, ['filterlog' => 0, 'suricata' => 1, 'fortigate' => 1]), null, 'disabled source ignored');

eq(tom_is_public_ip('185.220.101.5'), true, 'public v4');
foreach (['10.1.2.3', '192.168.1.1', '172.20.0.1', '127.0.0.1', '100.64.1.1', '203.0.113.10', '169.254.1.1', '::1', 'fe80::1', '2001:db8::1', 'fc00::1'] as $ip) {
    eq(tom_is_public_ip($ip), false, "non-public $ip");
}
eq(tom_is_public_ip('2a03:2880:f003:c07:face:b00c::2'), true, 'public v6');
$cfg = ['allowed_senders' => "203.0.113.1\n198.51.100.0/24", 'site_name' => 'HQ', 'lat' => 41, 'lon' => 29,
    'locations' => [['name' => 'ANK', 'lat' => 39.9, 'lon' => 32.9, 'senders' => '192.0.2.10, 192.0.2.11'],
                    ['name' => 'FRA', 'lat' => 50.1, 'lon' => 8.7, 'senders' => '10.20.0.0/16']]];
eq(tom_sender_allowed('198.51.100.7', $cfg), true, 'allow cidr');
eq(tom_sender_allowed('198.51.101.7', $cfg), false, 'reject outside');
eq(tom_sender_allowed('192.0.2.11', $cfg), true, 'location sender is allowed');
eq(tom_sender_allowed('1.2.3.4', ['allowed_senders' => '', 'locations' => $cfg['locations']]), true, 'empty list allows all');
eq([tom_location_for('192.0.2.10', $cfg), tom_location_for('10.20.5.5', $cfg), tom_location_for('203.0.113.1', $cfg)], [1, 2, 0], 'location mapping');
eq(array_column(tom_sites($cfg), 'name'), ['HQ', 'ANK', 'FRA'], 'sites list');
eq(tom_parse_line('devname="FG-Ankara" srcip=91.240.118.172 dstport=22 proto=6 action="deny"')['sensor'], 'FG-Ankara', 'fortigate devname');
eq(tom_mask_ip('185.220.101.5'), '185.220.101.x', 'mask v4');

$mm = $argv[1] ?? '';
if ($mm && is_file($mm)) {
    $db = new TOM_MMDB($mm);
    eq($db->metadata['database_type'], 'GeoIP2-City', 'mmdb type');
    $rec = $db->get('81.2.69.142');
    eq([$rec['country']['iso_code'] ?? null, $rec['city']['names']['en'] ?? null], ['GB', 'London'], 'mmdb v4 lookup');
    eq(is_float($rec['location']['latitude'] ?? null), true, 'mmdb double decode');
    $rec = $db->get('2001:218::1');
    eq($rec['country']['iso_code'] ?? null, 'JP', 'mmdb v6 lookup');
    eq($db->get('10.0.0.1'), null, 'mmdb miss');
    $rec = $db->get('216.160.83.56');
    echo '     216.160.83.56 → ' . json_encode([$rec['country']['iso_code'] ?? null, $rec['city']['names']['en'] ?? null, $rec['location'] ?? null]) . "\n";
}

echo $fail ? "\n$fail FAILED\n" : "\nall passed\n";
exit($fail ? 1 : 0);
