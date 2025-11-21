<?php
declare(strict_types=1);

/** 取得用戶端 IP（簡化版） */
function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/** 簡單的 POST */
function http_post(string $url, array $params, int $timeoutSec = 6): string {
    $ctx = stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => 'Content-type: application/x-www-form-urlencoded',
            'content' => http_build_query($params),
            'timeout' => $timeoutSec,
        ]
    ]);
    return @file_get_contents($url, false, $ctx) ?: '';
}

/** reCAPTCHA v3 驗證 */
function verify_recaptcha_v3(string $token, string $action = 'login', float $minScore = 0.5): array {
    // 建議從環境變數或設定檔讀取，不要寫死
    $secret = $_ENV['RECAPTCHA_SECRET'] ?? ($_SERVER['RECAPTCHA_SECRET'] ?? '');
    if ($secret === '' || $token === '') {
        return ['ok' => false, 'reason' => 'recaptcha_config_or_token_missing'];
    }

    $resp = http_post('https://www.google.com/recaptcha/api/siteverify', [
        'secret'   => $secret,
        'response' => $token,
        'remoteip' => client_ip(),
    ]);

    $data = json_decode($resp, true) ?: [];

    if (($data['success'] ?? false) !== true) {
        return ['ok' => false, 'reason' => 'recaptcha_api_fail', 'data' => $data];
    }
    if (($data['action'] ?? '') !== $action) {
        return ['ok' => false, 'reason' => 'recaptcha_action_mismatch', 'data' => $data];
    }
    if (($data['score'] ?? 0.0) < $minScore) {
        return ['ok' => false, 'reason' => 'recaptcha_low_score', 'score' => $data['score'] ?? 0];
    }
    return ['ok' => true, 'score' => $data['score'] ?? 0];
}
