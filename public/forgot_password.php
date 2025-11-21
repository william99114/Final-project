<?php
declare(strict_types=1);
session_start();

/* 偵錯用（上線請關） */
error_reporting(E_ALL);
ini_set('display_errors','1');
ini_set('log_errors','1');
ini_set('error_log','/var/log/php_errors.log');

/* 時區設定 */
date_default_timezone_set('Asia/Taipei');

/** 統一表名 */
define('PW_RESET_TABLE', 'password_resets');

require_once __DIR__ . '/../lib/auth.php';
require_once __DIR__ . '/../include/mailer.php';
require_once __DIR__ . '/../include/mail_templates.php';

/** HTML escape */
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

$msg = $ok = '';
$actuallySent = false;   // ★★★ 新增：實際是否有寄信

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* ==========================================
       (1) Rate Limit：每 IP 每 60 秒最多 3 次
       ========================================== */
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    $stmt = $pdo->prepare("
        SELECT attempts, last_attempt
        FROM password_reset_rate_limit
        WHERE ip = ?
    ");
    $stmt->execute([$ip]);
    $rl = $stmt->fetch();

    $now = time();

    if ($rl) {
        $last = strtotime($rl['last_attempt']);

        if ($now - $last < 60 && $rl['attempts'] >= 3) {
            $msg = "請稍後再試。";
        }

        if (!$msg) {
            if ($now - $last < 60) {
                $pdo->prepare("
                    UPDATE password_reset_rate_limit
                    SET attempts = attempts + 1, last_attempt = NOW()
                    WHERE ip = ?
                ")->execute([$ip]);
            } else {
                $pdo->prepare("
                    UPDATE password_reset_rate_limit
                    SET attempts = 1, last_attempt = NOW()
                    WHERE ip = ?
                ")->execute([$ip]);
            }
        }

    } else {
        $pdo->prepare("
            INSERT INTO password_reset_rate_limit (ip, attempts, last_attempt)
            VALUES (?, 1, NOW())
        ")->execute([$ip]);
    }


    /* ==========================================
       (2) 若 Rate Limit 阻擋 → 不繼續
       ========================================== */
    if ($msg) {
        // 顯示錯誤訊息即可
    } else {

        /* ==========================================
           (3) CAPTCHA 驗證
           ========================================== */
        $captcha = trim($_POST['captcha'] ?? '');

        if (!isset($_SESSION['VerifyCode']) ||
            strtolower($captcha) !== strtolower($_SESSION['VerifyCode'])) {

            $msg = '驗證碼錯誤，請再試一次。';

        } else {

            unset($_SESSION['VerifyCode']); // 使用後作廢

            /* ==========================================
               (4) Email 檢查
               ========================================== */
            $email = trim($_POST['email'] ?? '');

            if (!preg_match('/@o365\.ttu\.edu\.tw$/', $email)) {
                $msg = '請輸入學校信箱（@o365.ttu.edu.tw）';

            } else {

                $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
                $stmt->execute([$email]);
                $user = $stmt->fetch();

                $ok = '若信箱存在，已寄送重設連結（5 分鐘內有效）。';

                if ($user) {
                    $userId = (int)$user['id'];

                    /* ======================================
                       (A) 防濫用：5 分鐘內不能重寄
                       ====================================== */
                    $stmt = $pdo->prepare("
                        SELECT id
                        FROM ".PW_RESET_TABLE."
                        WHERE user_id = ? AND used = 0 AND expires_at > NOW()
                        LIMIT 1
                    ");
                    $stmt->execute([$userId]);
                    $existing = $stmt->fetch();

                    if ($existing) {
                        // ★★★ 這次沒有寄新信
                        $actuallySent = false;
                        goto END_RESET_FLOW;
                    }

                    /* ======================================
                       (B) 產生新的 Token & 寄信
                       ====================================== */

                    // 作廢舊 token
                    $pdo->prepare("
                        UPDATE ".PW_RESET_TABLE."
                        SET used = 1, used_at = NOW()
                        WHERE user_id = ? AND used = 0
                    ")->execute([$userId]);

                    // 建立 token
                    $token = bin2hex(random_bytes(32));
                    $hash  = hash('sha256', $token);
                    $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;

                    // 儲存 token（有效 5 分鐘）
                    $sql = "
                        INSERT INTO ".PW_RESET_TABLE."
                            (user_id, token_hash, expires_at, ip, user_agent)
                        VALUES
                            (?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE), ?, ?)
                    ";
                    $pdo->prepare($sql)->execute([$userId, $hash, $ip, $ua]);

                    // 產生重設連結
                    $proto  = $_SERVER['HTTP_X_FORWARDED_PROTO']
                        ?? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
                    $uriDir = rtrim(dirname($_SERVER['REQUEST_URI']), '/\\');
                    $base   = $proto.'://'.$_SERVER['HTTP_HOST'].($uriDir === '.' ? '' : $uriDir);
                    $link   = $base.'/reset_password.php?token='.urlencode($token);


                    // ★★★ 加上這一行（載入信件模板）
                    [$subject, $html, $text] = tpl_reset_password($email, $link);

                    // 寄信（成功才算 actuallySent）
                    try {
                        send_mail($email, $subject, $html, $text);
                        $actuallySent = true;   // ★★★ 有寄出
                    } catch (Throwable $e) {
                        error_log('Forgot mail send failed: '.$e->getMessage());
                    }

                    if ((getenv('APP_ENV') ?: '') === 'local') {
                        $ok .= '<br><code>'.h($link).'</code>';
                    }
                }

END_RESET_FLOW:
                ;
            }
        }
    }
}
?>

<?php
$pageTitle = '重設密碼';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2 class="title">重設密碼</h2>

  <?php if ($msg): ?>
      <div class="msg"><?= h($msg) ?></div>
  <?php endif; ?>

  <?php if ($ok): ?>
      <div class="msg ok">
          <?= $ok ?>
          <?php if (!$actuallySent): ?>
              <br><small>（你已在 5 分鐘內申請過，因此本次沒有再次寄送。）</small>
          <?php endif; ?>
      </div>
  <?php endif; ?>

  <?php if (!$ok): ?>
  <form method="post" autocomplete="off">
    <div class="row">
      <label for="email">學校信箱</label>
      <input class="input" id="email" name="email" type="email" required
             pattern=".+@o365\.ttu\.edu\.tw$" placeholder="xxx@o365.ttu.edu.tw">
    </div>

    <div class="row">
      <label for="captcha">驗證碼</label>

      <div class="captcha-group">
      <input class="input" id="captcha" name="captcha" type="text" required placeholder="請輸入驗證碼">

      <div class="captcha-visual">
        <img src="./captcha.php" id="captchaImg" alt="captcha"
             class="captcha-img" width="200" height="60">

        <button type="button" id="refresh-btn" aria-label="換一張" class="icon-btn" onclick="refreshCaptcha()">
          <svg viewBox="0 0 24 24" class="icon">
            <path d="M17.65 6.35A7.95 7.95 0 0 0 12 4a8 8 0 1 0 7.75 6h-2.1A6 6 0 1 1 12 6
            c1.3 0 2.5.42 3.47 1.13L13 9.6h7V2.6l-2.35 2.35z" fill="currentColor"></path>
          </svg>
        </button>
      </div>
  </div>
      
    </div>

    <button class="btn primary" type="submit">寄送重設連結</button>
  </form>
  <?php endif; ?>

  <p class="muted"><a class="link" href="./login.php">返回登入</a></p>
</div>

<script>
function refreshCaptcha(){
  const btn = document.getElementById('refresh-btn');
  const img = document.getElementById('captchaImg');
  if (!img) return;
  btn.classList.add('spin');

  const base = img.dataset.base || img.src.split('?')[0];
  img.dataset.base = base;

  img.src = base + '?refresh=1&ts=' + Date.now();

  const stop = () => {
    btn.classList.remove('spin');
    img.removeEventListener('load', stop);
    img.removeEventListener('error', stop);
  };

  img.addEventListener('load', stop);
  img.addEventListener('error', stop);
}
</script>

<?php include __DIR__ . '/../templates/footer.php'; ?>
