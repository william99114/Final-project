<?php
// public/verify_totp_bind.php (修正版)
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php'; // 應包含 $pdo, totp_verify(), log_login()

// 1. 取得並驗證從表單送來的 token 和 code
$token = $_POST['token'] ?? '';
$code = trim($_POST['code'] ?? '');

// 2. 驗證 magic link token 的有效性
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    header('Location: ./login.php'); // token 格式不對，直接回登入頁
    exit;
}
$s = $pdo->prepare("SELECT * FROM email_magic_links WHERE token=? AND purpose='bind_totp' LIMIT 1");
$s->execute([$token]);
$link = $s->fetch(PDO::FETCH_ASSOC);

if (!$link || !empty($link['used_at']) || new DateTime() > new DateTime($link['expires_at'])) {
    $error_msg = urlencode('綁定連結無效或已過期，請重新操作。');
    header("Location: ./login.php?msg=$error_msg");
    exit;
}
$userId = (int)$link['user_id'];

// 3. 從資料庫取得該使用者的 TOTP secret
$q = $pdo->prepare("SELECT secret FROM totp_secrets WHERE user_id=? ORDER BY created_at DESC LIMIT 1");
$q->execute([$userId]);
$row = $q->fetch(PDO::FETCH_ASSOC);

if (!$row || empty($row['secret'])) {
    $error_msg = urlencode('找不到您的驗證設定，請重新註冊或聯繫管理員。');
    header('Location: ./bind_totp_email.php?token=' . $token . '&err=' . $error_msg);
    exit;
}

// 4. 驗證使用者輸入的 6 位數驗證碼
if (!totp_verify($row['secret'], $code)) {
    $error_msg = urlencode('驗證碼錯誤，請再試一次。');
    header('Location: ./bind_totp_email.php?token=' . $token . '&err=' . $error_msg);
    exit;
}

// 5. 驗證成功！直接執行登入程序
try {
    $pdo->beginTransaction();

    // 5a. 標記 magic link 已使用
    $pdo->prepare("UPDATE email_magic_links SET used_at = NOW() WHERE id=?")->execute([$link['id']]);
    
    // 5b. 如果有 is_first_login 欄位，更新它
    $pdo->prepare("UPDATE users SET is_first_login = 'N' WHERE id = ?")->execute([$userId]);

    // 5c. 從資料庫取得完整的 user info 來寫入 session
    $userStmt = $pdo->prepare("SELECT id, email, name FROM users WHERE id = ?");
    $userStmt->execute([$userId]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        throw new Exception("綁定成功後找不到使用者資料，無法登入。");
    }

    // 5d. 清除所有可能存在的待處理 session
    unset($_SESSION['pending_user']);
    unset($_SESSION['force_totp_setup_user']);

    // 5e. 寫入正式的登入 session
    $_SESSION['user'] = [
        'id'    => (int)$user['id'],
        'email' => $user['email'],
        'name'  => $user['name'],
    ];

    // 5f. 記錄這一次成功的登入
    log_login($pdo, (int)$user['id'], $user['email'], true);

    $pdo->commit();

    // 5g. 成功登入，直接導向到主頁！
    header('Location: ./dashboard.php');
    exit;

} catch (Throwable $e) {
    $pdo->rollBack();
    error_log('Bind and login failed: ' . $e->getMessage());
    $error_msg = urlencode('系統發生錯誤，無法完成登入。');
    header('Location: ./login.php?msg=' . $error_msg);
    exit;
}