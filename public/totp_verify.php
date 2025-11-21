<?php
// public/totp_verify.php — 二步驗證（學號版 + 回原本UI）
declare(strict_types=1);
ini_set('display_errors', 1); // 開發用，上線建議關閉或記錄到檔案
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']),
    ]);
}
session_start();

require_once __DIR__ . '/../lib/auth.php';   // 需有 $pdo、verify_totp_and_login()

// 期待 login.php 在密碼正確後已放入：['id','student_id','name']
$pending = $_SESSION['pending_user'] ?? null;
if (!$pending || empty($pending['student_id'])) {
    header('Location: ./login.php'); exit;
}
$studentId = (string)$pending['student_id'];

// CSRF
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$csrf = $_SESSION['csrf'];

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
        http_response_code(400); exit('Bad Request');
    }
    $code = preg_replace('/\D+/', '', $_POST['code'] ?? '');

    if ($code !== '' && verify_totp_and_login($pdo, $code)) {
        // 第一次登入就設為 N（若欄位存在）
        try {
            $stmt = $pdo->prepare("UPDATE users SET is_first_login='N' WHERE id=? AND is_first_login='Y'");
            $stmt->execute([ (int)($_SESSION['user']['id'] ?? 0) ]);
        } catch (Throwable $e) { /* ignore, 但記 log */
            error_log('Mark first login N failed: ' . $e->getMessage());
        }
        header('Location: ./dashboard.php'); exit;
    } else {
        $msg = '驗證碼錯誤或已過期，請再試一次';
    }
}

$pageTitle = '二步驗證';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2>二步驗證</h2>

  <form method="post" autocomplete="one-time-code">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">

    <div class="row">
      <label>學號：</label>
      <input type="text" value="<?= htmlspecialchars($studentId) ?>" disabled>
    </div>

    <div class="row">
      <label>驗證碼</label>
      <input name="code" inputmode="numeric" pattern="\d{6}" maxlength="6" required placeholder="請輸入 6 位數 TOTP">
    </div>

    <button class="btn" type="submit">驗證並登入</button>
  </form>

  <?php if ($msg): ?>
    <div class="msg"><?= htmlspecialchars($msg) ?></div>
  <?php endif; ?>

  <p style="margin-top:8px;">
    <a class="link" href="./login.php">返回登入</a>
  </p>
</div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
