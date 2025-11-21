<?php
declare(strict_types=1);

// 🟩 啟動 session（只需一次）
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 🟩 清除登入相關暫存資料
unset(
    $_SESSION['pending_login_id'],
    $_SESSION['VerifyCode'],
    $_SESSION['csrf'],
    $_SESSION['csrf_time']
);

// 🟩 判斷錯誤類型
$type = $_GET['type'] ?? 'invalid';

switch ($type) {
    case 'expired':
        $title = '驗證碼已過期';
        $message = 'CSRF Token 已過期，請重新整理登入頁面再試。';
        break;

    case 'invalid':
    default:
        $title = '非法請求';
        $message = '驗證失敗，請勿重複提交或修改表單內容。';
        break;
}

$pageTitle = $title;
include __DIR__ . '/../templates/header.php';
?>
<div class="card" style="text-align:center;">
  <h2><?= htmlspecialchars($title) ?></h2>
  <p style="margin-top:12px;"><?= htmlspecialchars($message) ?></p>
  <p style="margin-top:24px;">
    <a href="./login.php" class="btn">返回登入頁面</a>
  </p>
</div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
