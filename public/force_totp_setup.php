<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/auth.php'; // 提供 $pdo, session_start()
require_once __DIR__ . '/../lib/totp.php'; // 提供 totp 相關函式

// 若 Session 中沒有待綁定的使用者資訊，就回登入
if (!isset($_SESSION['force_totp_setup_user'])) {
    header('Location: ./login.php');
    exit;
}

$user   = $_SESSION['force_totp_setup_user'];
$userId = (int)$user['id'];
// 📍 改：以學號為顯示與 otpauth 帳號
$accountLabel = $user['student_id'] ?? ''; 

$secret = '';
$otpauth = '';
$err = '';

try {
    // 查詢或建立此使用者的 TOTP secret
    $s = $pdo->prepare("SELECT secret FROM totp_secrets WHERE user_id=? ORDER BY created_at DESC LIMIT 1");
    $s->execute([$userId]);
    $row = $s->fetch(PDO::FETCH_ASSOC);

    if ($row && !empty($row['secret'])) {
        $secret = $row['secret'];
    } else {
        $secret = totp_generate_secret();
        $ins = $pdo->prepare("INSERT INTO totp_secrets (user_id, secret, created_at) VALUES (?, ?, NOW())");
        $ins->execute([$userId, $secret]);
    }

    // 📍 改：otpauth 第二參數用學號
    $otpauth = totp_build_uri('校園登入系統', $accountLabel, $secret);

} catch (Throwable $e) {
    $err = '系統發生錯誤，無法產生驗證密鑰：' . $e->getMessage();
    error_log('Force TOTP Setup Error: ' . $e->getMessage());
}

$pageTitle = '首次登入安全設定';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2>首次登入安全設定</h2>
  <p class="subtitle">為保障您的帳號安全，首次登入需綁定兩步驟驗證。</p>
  
  <?php if ($err): ?>
    <div class="msg"><?= htmlspecialchars($err) ?></div>
  <?php else: ?>
    <?php if (!empty($_GET['err'])): ?>
      <div class="msg"><?= htmlspecialchars($_GET['err']) ?></div>
    <?php endif; ?>

    <p>學號：<strong><?= htmlspecialchars($accountLabel) ?></strong></p>
    <p>請使用 Microsoft Authenticator 或 Google Authenticator 等驗證器 App 掃描下方 QR Code，或手動輸入密鑰，然後輸入 App 顯示的 6 位數驗證碼以完成綁定。</p>
    
    <div id="qrcode" style="margin: 24px auto; width: 240px; background: #fff; padding: 16px; border-radius: 8px;"></div>
    
    <p>如果無法掃描，請手動輸入密鑰：<br><code><?= htmlspecialchars($secret) ?></code></p>

    <form method="post" action="verify_forced_totp.php" autocomplete="one-time-code">
      <div class="row">
        <label for="code">6 位數驗證碼</label>
        <input id="code" name="code" inputmode="numeric" pattern="\d{6}" maxlength="6" required autofocus>
      </div>
      <button class="btn primary block" type="submit">驗證並完成設定</button>
    </form>
    
    <p style="margin-top:16px; text-align:center;">
      <a class="link" href="./logout.php">取消並登出</a>
    </p>

    <script src="./assets/qrcode.min.js"></script>
    <script>
      new QRCode(
        document.getElementById('qrcode'),
        {
          text: <?= json_encode($otpauth) ?>,
          width: 208,
          height: 208,
          correctLevel: QRCode.CorrectLevel.H
        }
      );
    </script>
  <?php endif; ?>
</div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
