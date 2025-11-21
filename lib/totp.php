<?php
// lib/totp.php
declare(strict_types=1);

/** 產生 Base32 祕鑰（預設 20 bytes -> Base32 約 32 字元） */
function totp_generate_secret(int $bytes = 20): string {
    $raw = random_bytes($bytes);
    return rtrim(base32_encode($raw), '='); // 無填充
}

/** 產生 otpauth URI（可給 Microsoft/Google Authenticator 掃描） */
function totp_build_uri(string $issuer, string $accountEmail, string $secret, int $digits = 6, int $period = 30): string {
    $label   = rawurlencode("{$issuer}:{$accountEmail}");
    $issuerQ = rawurlencode($issuer);
    $secretQ = rawurlencode($secret);
    return "otpauth://totp/{$label}?secret={$secretQ}&issuer={$issuerQ}&algorithm=SHA1&digits={$digits}&period={$period}";
}

/** 驗證 TOTP 六碼（接受時間偏移 ±1 period） */
function totp_verify(string $secret, string $code, int $period = 30, int $digits = 6, int $skew = 1): bool {
    $code = preg_replace('/\s+/', '', $code);
    if (!preg_match('/^\d{6}$/', $code)) return false;
    $tm = (int)floor(time() / $period);
    for ($i = -$skew; $i <= $skew; $i++) {
        if (hash_equals($code, totp_at($secret, $tm + $i, $digits))) {
            return true;
        }
    }
    return false;
}

/** 計算某時間步的 TOTP */
function totp_at(string $secret, int $timeStep, int $digits): string {
    $key = base32_decode($secret);
    $binTime = pack('N*', 0) . pack('N*', $timeStep); // 8 bytes big-endian
    $hmac = hash_hmac('sha1', $binTime, $key, true);
    $offset = ord(substr($hmac, -1)) & 0x0F;
    $part = substr($hmac, $offset, 4);
    $num = (ord($part[0]) & 0x7F) << 24
         | (ord($part[1]) & 0xFF) << 16
         | (ord($part[2]) & 0xFF) << 8
         | (ord($part[3]) & 0xFF);
    $otp = $num % (10 ** $digits);
    return str_pad((string)$otp, $digits, '0', STR_PAD_LEFT);
}

/** ===== Base32 encode/decode（RFC4648，不帶填充）===== */
function base32_encode(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $binary = '';
    foreach (str_split($data) as $c) $binary .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    $groups = str_split($binary, 5);
    $out = '';
    foreach ($groups as $g) {
        if (strlen($g) < 5) $g = str_pad($g, 5, '0', STR_PAD_RIGHT);
        $out .= $alphabet[bindec($g)];
    }
    return $out;
}
function base32_decode(string $b32): string {
    $b32 = strtoupper($b32);
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $map = array_flip(str_split($alphabet));
    $binary = '';
    foreach (str_split($b32) as $ch) {
        if (!isset($map[$ch])) continue;
        $binary .= str_pad(decbin($map[$ch]), 5, '0', STR_PAD_LEFT);
    }
    $bytes = str_split($binary, 8);
    $out = '';
    foreach ($bytes as $byte) {
        if (strlen($byte) < 8) continue;
        $out .= chr(bindec($byte));
    }
    return $out;
}
