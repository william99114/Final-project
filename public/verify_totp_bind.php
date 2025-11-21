<?php
// public/verify_totp_bind.php — 綁定後驗證並直接登入（學號版）
declare(strict_types=1);

require_once __DIR__ . '/../lib/auth.php'; // 應包含 $pdo, totp_verify(), log_login()
if (session_status() === PHP_SESSION_NONE) session_start();

// 1) 取得表單參數
$token = $_POST['token'] ?? '';
$code  = trim($_POST['code'] ?? '');

// 2) 驗證 magic link token 的有效性
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    header('Location: ./login.php');
    exit;
}

$s = $pdo->prepare("SELECT * FROM email_magic_links WHERE token=? AND purpose='bind_totp' LIMIT 1");
$s->execute([$token]);
$link = $s->fetch(PDO::FETCH_ASSOC);

if (
    !$link ||
    !empty($link['used_at']) ||
    (new DateTime()) > new DateTime($link['expires_at'])
) {
    $error_msg = urlencode('綁定連結無效或已過期，請重新操作。');
    header("Location: ./login.php?msg={$error_msg}");
    exit;
}

$userId = (int)$link['user_id'];

// 3) 取使用者 TOTP secret
$q = $pdo->prepare("SELECT secret FROM totp_secrets WHERE user_id=? ORDER BY created_at DESC LIMIT 1");
$q->execute([$userId]);
$row = $q->fetch(PDO::FETCH_ASSOC);

if (!$row || empty($row['secret'])) {
    $error_msg = urlencode('找不到您的驗證設定，請重新操作或聯繫管理員。');
    header('Location: ./bind_totp_email.php?token=' . urlencode($token) . '&err=' . $error_msg);
    exit;
}

// 4) 驗證 6 位數驗證碼
if (!totp_verify($row['secret'], $code)) {
    $error_msg = urlencode('驗證碼錯誤，請再試一次。');
    header('Location: ./bind_totp_email.php?token=' . urlencode($token) . '&err=' . $error_msg);
    exit;
}

// 5) 驗證成功 → 標記使用、更新首次登入、建立 session、寫登入紀錄
try {
    $pdo->beginTransaction();

    // 5a) 標記 magic link 已使用
    $pdo->prepare("UPDATE email_magic_links SET used_at = NOW() WHERE id=?")->execute([$link['id']]);

    // 5b) 更新 is_first_login
    $pdo->prepare("UPDATE users SET is_first_login = 'N' WHERE id = ?")->execute([$userId]);

    // 5c) 取完整使用者資訊（📍 改：取出 student_id）
    $userStmt = $pdo->prepare("SELECT id, student_id, email, name FROM users WHERE id = ? LIMIT 1");
    $userStmt->execute([$userId]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        throw new Exception('綁定成功後找不到使用者資料，無法登入。');
    }

    // 5d) 清除待處理 session
    unset($_SESSION['pending_user'], $_SESSION['force_totp_setup_user']);

    // 5e) 寫入正式登入 session（📍 改：放入 student_id）
    $_SESSION['user'] = [
        'id'         => (int)$user['id'],
        'student_id' => $user['student_id'],
        'name'       => $user['name'],
    ];

    // 5f) 記錄一次成功登入（📍 改：把學號寫入第二參數；
    // 若你的 login_logs 欄位仍叫 email，會以學號填入該欄位以相容）
    log_login($pdo, (int)$user['id'], $user['student_id'], true);

    $pdo->commit();

    // 5g) 導向主頁
    header('Location: ./dashboard.php');
    exit;

} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log('Bind and login failed: ' . $e->getMessage());
    $error_msg = urlencode('系統發生錯誤，無法完成登入。');
    header('Location: ./login.php?msg=' . $error_msg);
    exit;
}
