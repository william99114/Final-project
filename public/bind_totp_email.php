<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php'; // 提供 $pdo, session_start()

// // 除錯（測完請關閉）
// ini_set('display_errors','1');
// error_reporting(E_ALL);

// 產生 Base32 祕鑰（獨立於 totp.php）
function b32_random(int $len = 32): string {
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $s = '';
  for ($i = 0; $i < $len; $i++) $s .= $alphabet[random_int(0, 31)];
  return $s;
}

// CSRF token
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

$err = '';
$emailVal = '';   // 錯誤畫面用於重新寄送
$secret = '';
$otpauth = '';

// 允許錯誤導回時用 GET 帶入 email，讓重新寄送可用
if (isset($_GET['email']) && filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
  $emailVal = $_GET['email'];
}

try {
  $token = $_GET['token'] ?? '';
  if ($token === '' || $token === null) {
    throw new RuntimeException('缺少連結參數（token）。');
  }

  // ✅ 先查 DB（即使 token 格式不對也先查），以便取出 email
  $stmt = $pdo->prepare("SELECT * FROM email_magic_links WHERE token=? AND purpose='bind_totp' LIMIT 1");
  $stmt->execute([$token]);
  $link = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$link) {
    throw new RuntimeException('連結無效或不存在。');
  }

  $userId = (int)$link['user_id'];

  // 先抓 email（即使後面要丟錯，也能讓重新寄送可用）
  $u = $pdo->prepare("SELECT email FROM users WHERE id=? LIMIT 1");
  $u->execute([$userId]);
  $user = $u->fetch(PDO::FETCH_ASSOC);
  if ($user && !empty($user['email'])) {
    $emailVal = $user['email'];
  }

  // 再做格式檢查（這時候就算錯，也能顯示「重新寄送」）
  if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    throw new RuntimeException('連結格式錯誤（token）。');
  }

  // 檢查已使用 / 期限
  if (!empty($link['used_at'])) {
    throw new RuntimeException('此連結已使用。');
  }
  if (new DateTime() > new DateTime($link['expires_at'])) {
    throw new RuntimeException('連結已過期。');
  }

  if (!$user) {
    throw new RuntimeException('找不到使用者。');
  }

  // 取得/建立 TOTP secret
  $s = $pdo->prepare("SELECT secret FROM totp_secrets WHERE user_id=? ORDER BY created_at DESC LIMIT 1");
  $s->execute([$userId]);
  $row = $s->fetch(PDO::FETCH_ASSOC);

  if ($row && !empty($row['secret'])) {
    $secret = $row['secret'];
  } else {
    $secret = b32_random(32);
    $ins = $pdo->prepare("INSERT INTO totp_secrets (user_id, secret, created_at) VALUES (?, ?, NOW())");
    $ins->execute([$userId, $secret]);
  }

  // otpauth URI
  $issuer = rawurlencode('TTU-Auth');
  $label  = rawurlencode($user['email']);
  $otpauth = "otpauth://totp/{$issuer}:{$label}?secret={$secret}&issuer={$issuer}&digits=6&period=30";

} catch (Throwable $e) {
  $err = $e->getMessage();
}

$pageTitle = '綁定 Microsoft Authenticator';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2>綁定 Microsoft Authenticator</h2>

  <?php if ($err): ?>
    <div class="msg"><?= htmlspecialchars($err) ?></div>

    <!-- 錯誤時提供重新寄送 -->
    <form method="post" action="./resend_bind_totp.php" style="margin-top:12px;">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
      <input type="hidden" name="email" value="<?= htmlspecialchars($emailVal) ?>">
      <button class="btn" type="submit" <?= $emailVal ? '' : 'disabled' ?>>重新寄送驗證郵件</button>
      <?php if (!$emailVal): ?>
        <div class="muted" style="margin-top:6px;">無法識別帳號，請回登入頁再操作。</div>
      <?php endif; ?>
    </form>

    <p style="margin-top:8px;"><a class="link" href="./login.php">返回登入</a></p>

  <?php else: ?>
    <?php if (!empty($_GET['err'])): ?>
      <div class="msg"><?= htmlspecialchars($_GET['err']) ?></div>
    <?php endif; ?>

    <p>請用手機 App 掃描下方 QR，或手動輸入祕鑰後，輸入 6 碼完成綁定。</p>
    <div id="qrcode" style="margin:12px 0;"></div>
    <p>祕鑰：<code><?= htmlspecialchars($secret) ?></code></p>

    <form method="post" action="verify_totp_bind.php" autocomplete="one-time-code">
      <input type="hidden" name="token" value="<?= htmlspecialchars($_GET['token'] ?? '') ?>">
      <div class="row">
        <label>驗證碼</label>
        <input name="code" inputmode="numeric" pattern="\d{6}" maxlength="6" required>
      </div>
      <button class="btn" type="submit">驗證並完成綁定</button>
    </form>

    <p style="margin-top:8px;"><a class="link" href="./login.php">返回登入</a></p>
    <p style="margin-top:8px;"><a class="link" href="./register.php">返回註冊</a></p>

    <script src="/auth2fa/public/assets/qrcode.min.js"></script>
    <script>
      new QRCode(
        document.getElementById('qrcode'),
        { text: <?= json_encode($otpauth) ?>, width: 240, height: 240 }
      );
    </script>
  <?php endif; ?>
</div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
