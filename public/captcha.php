<?php
// captcha.php — 120x40 小畫布、大字體(28pt) + 診斷標頭
declare(strict_types=1);

session_set_cookie_params([
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
]);
session_start();

// 重新產生
if (isset($_GET['refresh'])) unset($_SESSION['VerifyCode']);
if (empty($_SESSION['VerifyCode'])) {
    $_SESSION['VerifyCode'] = (function (int $len = 6): string {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $n = strlen($alphabet) - 1; $out = '';
        for ($i = 0; $i < $len; $i++) $out .= $alphabet[random_int(0, $n)];
        return $out;
    })();
}
$code = strtoupper((string)$_SESSION['VerifyCode']);
$len  = strlen($code);

// === 畫布 ===
$width = 120; $height = 40;
if (!function_exists('imagecreatetruecolor')) { http_response_code(500); exit('GD not available'); }

header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// === 診斷資訊（在 Network headers 看到） ===
$gdInfo = function_exists('gd_info') ? gd_info() : [];
$hasFT  = !empty($gdInfo['FreeType Support']);
header('X-Captcha-FreeType: '.($hasFT ? 'yes' : 'no'));

// 嘗試多個字型路徑：依序取第一個存在的
$candidates = [
    __DIR__ . '/captcha.ttf',
    __DIR__ . '/LobsterTwo-Bold.otf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
    '/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf',
];
$fontPath = null;
foreach ($candidates as $p) {
    if (is_readable($p)) { $fontPath = $p; break; }
}
$canTTF = $hasFT && function_exists('imagettftext') && $fontPath;
header('X-Captcha-FontMode: '.($canTTF ? 'TTF' : 'bitmap'));
if ($fontPath) header('X-Captcha-FontPath: '.$fontPath);

$img = imagecreatetruecolor($width, $height);
$bg  = imagecolorallocate($img, 255, 255, 255);
imagefill($img, 0, 0, $bg);

// 干擾（少一點讓字清楚）
for ($i = 0; $i < 4; $i++) {
    $c = imagecolorallocate($img, random_int(180,220), random_int(180,220), random_int(180,220));
    imageline($img, random_int(0,$width), random_int(0,$height), random_int(0,$width), random_int(0,$height), $c);
}
for ($i = 0; $i < 180; $i++) {
    $c = imagecolorallocate($img, random_int(0,240), random_int(0,240), random_int(0,240));
    imagesetpixel($img, random_int(0,$width-1), random_int(0,$height-1), $c);
}

// === 繪字 ===
if ($canTTF) {
    $fontSize = 20;              // 放大：28pt 剛好填滿 40px 高
    $xStart   = 6;
    $yBase    = (int)($height * 0.78); // 字基線約略位置
    $step     = (int)(($width - $xStart * 2) / $len) - 2; // 字間縫隙

    for ($i = 0; $i < $len; $i++) {
        $char  = $code[$i];
        $angle = random_int(-10, 10);
        $x     = $xStart + $i * $step + random_int(-1, 1);
        $y     = $yBase + random_int(-1, 1);
        $col   = imagecolorallocate($img, random_int(0,255), random_int(0,255), random_int(0,25));
        // 可選：加粗（畫兩次，微偏移）
        // imagettftext($img, $fontSize, $angle, $x+1, $y, $col, $fontPath, $char);
        imagettftext($img, $fontSize, $angle, $x, $y, $col, $fontPath, $char);
    }
} else {
    // 沒有 TTF：只能用 bitmap（會小）
    $black  = imagecolorallocate($img, 30, 30, 30);
    $font   = 5;
    $fw     = imagefontwidth($font);
    $fh     = imagefontheight($font);
    $totalW = $fw * $len;
    $x      = (int)(($width - $totalW) / 2);
    $y      = (int)(($height - $fh) / 2);
    imagestring($img, $font, $x, $y, $code, $black);
}

imagepng($img);
imagedestroy($img);
