<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php'; // 需提供 $pdo, session_start()

// // 除錯（測完請關閉）
// ini_set('display_errors','1');
// error_reporting(E_ALL);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  header('Location: ./login.php');
  exit;
}

// ---- CSRF ----
if (($_POST['csrf_token'] ?? '') !== ($_SESSION['csrf_token'] ?? '')) {
  header('Location: ./bind_totp_email.php?err=' . urlencode('CSRF 驗證失敗') . '&email=' . urlencode($_POST['email'] ?? ''));
  exit;
}

// ---- 取得 email ----
$email = trim((string)($_POST['email'] ?? ''));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  header('Location: ./bind_totp_email.php?err=' . urlencode('信箱格式不正確') . '&email=' . urlencode($email));
  exit;
}

// ---- 查使用者 ----
$stmt = $pdo->prepare('SELECT id, email FROM users WHERE email=? LIMIT 1');
$stmt->execute([$email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$user) {
  header('Location: ./bind_totp_email.php?err=' . urlencode('查無此帳號') . '&email=' . urlencode($email));
  exit;
}
$userId = (int)$user['id'];

// ---- 60 秒節流 ----
$key = 'resend_bind_totp_' . md5(strtolower($email));
$now = time();
if (!empty($_SESSION[$key]) && ($now - (int)$_SESSION[$key]) < 60) {
  $wait = 60 - ($now - (int)$_SESSION[$key]);
  header('Location: ./bind_totp_email.php?err=' . urlencode("請稍候再試（約 {$wait} 秒）") . '&email=' . urlencode($email));
  exit;
}

// ---- 產生新 token 並寫入 magic link ----
$token   = bin2hex(random_bytes(32));               // 64 hex
$expires = (new DateTime('+24 hours'))->format('Y-m-d H:i:s');

$ins = $pdo->prepare("
  INSERT INTO email_magic_links (user_id, token, purpose, expires_at, created_at)
  VALUES (?, ?, 'bind_totp', ?, NOW())
");
$ins->execute([$userId, $token, $expires]);

// ---- 拼信中的 URL（依你的實際路徑）----
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
       || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
       || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
       ? 'https' : 'http';
$host   = $_SERVER['HTTP_HOST'] ?? 'localhost';

// 如果此檔案在 /auth2fa/public/ 底下，調整路徑如下；若不是，改成你實際網址
$linkUrl = $scheme . '://' . $host . '/auth2fa/public/bind_totp_email.php?token=' . urlencode($token);

// ---- 寄信（用你既有的寄信函式）----
$subject = '綁定 Microsoft Authenticator 驗證連結';
$body    = "您好：<br><br>請在 24 小時內點擊以下連結完成綁定：<br>"
         . '<a href="'.$linkUrl.'">'.$linkUrl.'</a><br><br>'
         . '若非您本人操作，請忽略此信。';

// 嘗試呼叫你專案中既有的寄信函式
$sent = false;
if (function_exists('sendMail')) {
  $sent = (bool)sendMail($email, $subject, $body);
} elseif (function_exists('sendVerificationEmail')) {
  // 若你的專案用另外的函式名稱，這裡也支援
  $sent = (bool)sendVerificationEmail($email, $subject, $body);
}

$_SESSION[$key] = $now;

if ($sent) {
  // 成功導回登入頁或成功提示頁
  header('Location: ./login.php?msg=' . urlencode('已寄出驗證信，請前往信箱收信'));
  exit;
}

// 失敗導回並帶上 email，讓按鈕仍可用
header('Location: ./bind_totp_email.php?err=' . urlencode('寄送失敗，請稍後再試') . '&email=' . urlencode($email));
exit;
