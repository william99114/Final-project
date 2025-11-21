<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php';

// 密碼過了但 TOTP 未過 -> 去二次驗證
if (isset($_SESSION['pending_user'])) {
    header('Location: ./totp_verify.php'); exit;
}

// 已登入 -> dashboard；未登入 -> login
if (is_logged_in()) {
    header('Location: ./dashboard.php'); exit;
}
header('Location: ./login.php'); exit;
