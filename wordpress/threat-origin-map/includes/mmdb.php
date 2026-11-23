<?php
/**
 * Minimal pure-PHP reader for MaxMind DB (.mmdb) files — no Composer, no extension.
 * Implements the format spec at https://maxmind.github.io/MaxMind-DB/ (search tree + data section).
 * Reads with fseek/fread, so it works with a 60 MB City database inside a normal web request.
 */
defined('ABSPATH') || defined('TOM_CLI') || exit;

class TOM_MMDB_Error extends Exception {}

class TOM_MMDB {
    const MARKER = "\xAB\xCD\xEFMaxMind.com";

    private $fh;
    private $size;
    private $node_count;
    private $record_size;
    private $node_bytes;
    private $tree_size;
    private $data_start;
    private $ipv4_start = null;
    private $cache = [];
    public $metadata;

    public function __construct($path) {
        $fh = @fopen($path, 'rb');
        if (!$fh) {
            throw new TOM_MMDB_Error('Dosya açılamadı.');
        }
        $this->fh = $fh;
        $this->size = filesize($path);
        $tail_len = min($this->size, 128 * 1024);
        fseek($fh, $this->size - $tail_len);
        $tail = fread($fh, $tail_len);
        $pos = strrpos($tail, self::MARKER);
        if ($pos === false) {
            throw new TOM_MMDB_Error('MaxMind DB metadata bulunamadı.');
        }
        $meta_start = $this->size - $tail_len + $pos + strlen(self::MARKER);
        [$md] = $this->decode($meta_start, $meta_start);
        if (!is_array($md) || !isset($md['node_count'], $md['record_size'], $md['ip_version'])) {
            throw new TOM_MMDB_Error('Geçersiz metadata.');
        }
        $this->metadata = $md;
        $this->node_count = (int) $md['node_count'];
        $this->record_size = (int) $md['record_size'];
        if (!in_array($this->record_size, [24, 28, 32], true)) {
            throw new TOM_MMDB_Error('Desteklenmeyen record_size.');
        }
        $this->node_bytes = $this->record_size / 4;
        $this->tree_size = $this->node_bytes * $this->node_count;
        $this->data_start = $this->tree_size + 16;
        if ($this->data_start > $this->size) {
            throw new TOM_MMDB_Error('Bozuk dosya.');
        }
    }

    public function __destruct() {
        if ($this->fh) {
            fclose($this->fh);
        }
    }

    private function read($offset, $len) {
        if ($len === 0) {
            return '';
        }
        if ($offset < 0 || $offset + $len > $this->size) {
            throw new TOM_MMDB_Error('Dosya dışına okuma.');
        }
        fseek($this->fh, $offset);
        $s = fread($this->fh, $len);
        if ($s === false || strlen($s) !== $len) {
            throw new TOM_MMDB_Error('Okuma hatası.');
        }
        return $s;
    }

    private static function uint($bytes) {
        $v = 0;
        $n = strlen($bytes);
        for ($i = 0; $i < $n; $i++) {
            $v = ($v << 8) | ord($bytes[$i]);
        }
        return $v;
    }

    private function record($node, $bit) {
        $b = $this->read($node * $this->node_bytes, $this->node_bytes);
        switch ($this->record_size) {
            case 24:
                return self::uint(substr($b, $bit ? 3 : 0, 3));
            case 28:
                if ($bit) {
                    return ((ord($b[3]) & 0x0F) << 24) | self::uint(substr($b, 4, 3));
                }
                return ((ord($b[3]) & 0xF0) << 20) | self::uint(substr($b, 0, 3));
            default:
                return self::uint(substr($b, $bit ? 4 : 0, 4));
        }
    }

    /** Returns the decoded record for an IP string, or null. */
    public function get($ip) {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        $bits = strlen($packed) * 8;
        $node = 0;
        if ($bits === 32 && (int) $this->metadata['ip_version'] === 6) {
            if ($this->ipv4_start === null) {
                $n = 0;
                for ($i = 0; $i < 96 && $n < $this->node_count; $i++) {
                    $n = $this->record($n, 0);
                }
                $this->ipv4_start = $n;
            }
            $node = $this->ipv4_start;
        }
        for ($i = 0; $i < $bits && $node < $this->node_count; $i++) {
            $bit = (ord($packed[$i >> 3]) >> (7 - ($i & 7))) & 1;
            $node = $this->record($node, $bit);
        }
        if ($node <= $this->node_count) {
            return null; // == node_count means "no data"
        }
        $off = $node - $this->node_count - 16;
        if (isset($this->cache[$off])) {
            return $this->cache[$off];
        }
        [$val] = $this->decode($this->data_start + $off, $this->data_start);
        if (count($this->cache) > 5000) {
            $this->cache = [];
        }
        return $this->cache[$off] = $val;
    }

    /** Decodes one value at absolute $off. Returns [value, next absolute offset]. */
    private function decode($off, $base, $depth = 0) {
        if ($depth > 64) {
            throw new TOM_MMDB_Error('Çok derin veri.');
        }
        $ctrl = ord($this->read($off++, 1));
        $type = $ctrl >> 5;
        if ($type === 1) { // pointer
            $ss = ($ctrl >> 3) & 3;
            $vvv = $ctrl & 7;
            $b = $this->read($off, $ss + 1);
            $off += $ss + 1;
            switch ($ss) {
                case 0: $p = ($vvv << 8) | self::uint($b); break;
                case 1: $p = (($vvv << 16) | self::uint($b)) + 2048; break;
                case 2: $p = (($vvv << 24) | self::uint($b)) + 526336; break;
                default: $p = self::uint($b);
            }
            [$val] = $this->decode($base + $p, $base, $depth + 1);
            return [$val, $off];
        }
        if ($type === 0) {
            $type = 7 + ord($this->read($off++, 1));
        }
        $size = $ctrl & 0x1F;
        if ($size >= 29) {
            $n = $size - 28;
            $v = self::uint($this->read($off, $n));
            $off += $n;
            $size = [29 => 29 + $v, 30 => 285 + $v, 31 => 65821 + $v][$size];
        }
        switch ($type) {
            case 2: // utf8 string
                return [$this->read($off, $size), $off + $size];
            case 3: // double
                return [unpack('E', $this->read($off, 8))[1], $off + 8];
            case 4: // bytes
                return [$this->read($off, $size), $off + $size];
            case 5: case 6: case 9: case 10: // uint16/32/64/128
                $b = $this->read($off, $size);
                $v = $size <= 7 ? self::uint($b) : bin2hex($b);
                return [$v, $off + $size];
            case 7: // map
                $m = [];
                for ($i = 0; $i < $size; $i++) {
                    [$k, $off] = $this->decode($off, $base, $depth + 1);
                    [$v, $off] = $this->decode($off, $base, $depth + 1);
                    $m[(string) $k] = $v;
                }
                return [$m, $off];
            case 8: // int32
                $v = self::uint($this->read($off, $size));
                if ($size === 4 && $v >= 0x80000000) {
                    $v -= 0x100000000;
                }
                return [$v, $off + $size];
            case 11: // array
                $a = [];
                for ($i = 0; $i < $size; $i++) {
                    [$a[], $off] = $this->decode($off, $base, $depth + 1);
                }
                return [$a, $off];
            case 14: // boolean: value is the size
                return [$size !== 0, $off];
            case 15: // float
                return [unpack('G', $this->read($off, 4))[1], $off + 4];
            default:
                throw new TOM_MMDB_Error('Bilinmeyen veri türü ' . $type);
        }
    }
}
