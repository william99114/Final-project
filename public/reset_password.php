<?php
declare(strict_types=1);
session_start();

require_once __DIR__ . '/../lib/auth.php'; // 應提供 $pdo (PDO 連線)

/** 統一表名（之後要改只動這一行） */
define('PW_RESET_TABLE', 'password_resets');

/* （可選）為了顯示時間一致，設定 PHP 時區；實際過期判斷用 DB 的 NOW() */
date_default_timezone_set('Asia/Taipei');

/** HTML escape */
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

/** 確認 DB 連線可用 */
$pdo = $pdo ?? null;
if (!$pdo) { http_response_code(500); exit('DB not ready'); }

/** 取得 token（GET 第一次開啟、POST 送出表單都支援） */
$token = (string)($_GET['token'] ?? $_POST['token'] ?? '');
if ($token === '') { http_response_code(400); exit('缺少 token'); }

/** 比對用：只把 token 的雜湊存 DB，避免明文落地 */
$tokenHash = hash('sha256', $token);

/* ---------------------------------------------------------
   撈取 token 對應的資料：
   - pr.used = 0   → 尚未使用
   - pr.expires_at > NOW() → 以「資料庫時鐘」為準，避免時區不一致
--------------------------------------------------------- */
$stmt = $pdo->prepare("
  SELECT pr.id AS pr_id, pr.user_id, pr.expires_at, pr.used, u.id AS uid, u.email
  FROM ".PW_RESET_TABLE." pr
  JOIN users u ON u.id = pr.user_id
  WHERE pr.token_hash = ?
    AND pr.used = 0
    AND pr.expires_at > NOW()
  LIMIT 1
");
$stmt->execute([$tokenHash]);
$row = $stmt->fetch();

/** 找不到就視為無效或過期（避免洩漏帳號是否存在） */
if (!$row) { http_response_code(400); exit('重設連結無效或已過期'); }

/* 畫面狀態 */
$error = '';   // 表單錯誤訊息
$done  = false; // 是否已重設完成

/* ---------------------------------------------------------
   使用者送出新密碼
--------------------------------------------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $pwd  = (string)($_POST['password']  ?? '');
  $pwd2 = (string)($_POST['password2'] ?? '');

  // 基本密碼規則（可依需求加強）
  if (strlen($pwd) < 8) {
    $error = '密碼至少 8 碼';
  } elseif ($pwd !== $pwd2) {
    $error = '兩次輸入的密碼不一致';
  } else {
    // 交易內：更新密碼 → 作廢 token
    $pdo->beginTransaction();
    try {
      // 1) 更新使用者密碼雜湊
      $hash = password_hash($pwd, PASSWORD_DEFAULT);
      $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
          ->execute([$hash, $row['user_id']]);

      // 2) 標記本次 token 已使用，並記錄使用時間
      $pdo->prepare('UPDATE '.PW_RESET_TABLE.' SET used = 1, used_at = NOW() WHERE id = ?')
          ->execute([$row['pr_id']]);

      // （可選）若要強制重新綁 TOTP，解除下列註解：
      // $pdo->prepare('DELETE FROM totp_secrets WHERE user_id = ?')->execute([$row['user_id']]);
      // $pdo->commit();
      // header('Location: /auth2fa/public/totp_setup.html?email='.urlencode($row['email']));
      // exit;

      $pdo->commit();
      $done = true;
    } catch (Throwable $e) {
      $pdo->rollBack();
      $error = '更新失敗，請稍後再試';
      error_log('reset_password update error: '.$e->getMessage());
    }
  }
}

/* ---------------------------------------------------------
   頁面呈現（沿用你的模板）
--------------------------------------------------------- */
$pageTitle = '設定新密碼';
include __DIR__ . '/../templates/header.php';
?>
  <div class="card">
    <?php if ($done): ?>
      <h2 class="title">重設完成</h2>
      <div class="msg ok">你的密碼已更新，請回登入頁重新登入。</div>
      <p class="muted"><a class="link" href="./login.php">回登入</a></p>
    <?php else: ?>
      <h2 class="title">設定新密碼</h2>
      <p class="muted">帳號：<?= h($row['email']) ?></p>
      <?php if ($error): ?><div class="msg err"><?= h($error) ?></div><?php endif; ?>
      <form method="post" autocomplete="off">
        <input type="hidden" name="token" value="<?= h($token) ?>">
        <div class="row">
          <label for="password">新密碼（至少 8 碼）</label>
          <input class="input" id="password" name="password" type="password" required minlength="8">
        </div>
        <div class="row">
          <label for="password2">再輸入一次</label>
          <input class="input" id="password2" name="password2" type="password" required minlength="8">
        </div>
        <button class="btn primary" type="submit">更新密碼</button>
      </form>
    <?php endif; ?>
  </div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
