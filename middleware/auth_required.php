<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib/auth.php';

// 防止快取（避免登出後按返回鍵還看到內容）
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// 若還在密碼通過但尚未完成 TOTP 的「待驗證」狀態，導去二次驗證
if (isset($_SESSION['pending_user'])) {
    header('Location: /auth2fa/public/totp_verify.php');
    exit;
}

// 未登入就導回登入頁
if (!is_logged_in()) {
    header('Location: /auth2fa/public/login.php');
    exit;
}
