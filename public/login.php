<?php
declare(strict_types=1);
// login.php — 兩步驟登入：改為以「學號」登入
// 依賴：/lib/auth.php (包含 $pdo, 驗證函式, 鎖定函式)
// 依賴：./captcha.php (產生驗證碼圖片)
ini_set('display_errors', 1); // 開發用，上線建議關閉或記錄到檔案
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    ]);
}
session_start();

require_once __DIR__ . '/../lib/auth.php'; // 內含 $pdo、TOTP 等

// 📍 修改點：修改常數定義
// 📍 1. 鎖定規則：2 次機會 / 10 秒內
define('LOGIN_ATTEMPTS_LIMIT', 2); // 允許的最大連續失敗次數 (2 次機會)
define('LOGIN_BASE_PERIOD', 10);  // 基礎檢查週期 (檢查 10 秒內的失敗紀錄)

// 📍 2. 修改點：移除漸進式陣列，改成固定 60 秒
define('LOCKOUT_DURATION_SECONDS', 10); // 每次鎖定 10 秒)

// 🟩 3. IP 封鎖相關常數 (保留)
define('PERM_LOCK_TRIGGER_COUNT', 2); // 帳號被「暫時鎖定」 5 次
define('PERM_LOCK_LOG_CHECK', 4);  // 就去檢查最近 10 筆登入日誌
define('PERM_LOCK_IP_VARIETY', 3);   // 日誌中若有 3 個 (含) 以上的不同 IP，就永久鎖定該「學號」

// === CSRF（建議保留） ===
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
      $_SESSION['csrf_time'] = time();
}
$csrf = $_SESSION['csrf'];

$msg = '';
$step = 1;
$inputStudentId = ''; // 📍 改：原本是 $inputEmail

// 📍 改：統一產生驗證碼小工具
function gen_code(int $len = 6): string {
    $needBytes = (int)ceil($len / 2);
    return substr(strtoupper(bin2hex(random_bytes($needBytes))), 0, $len);
}


$userIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown_ip';

// 🟩 4. 檢查 IP 是否已被永久封鎖 (保留)
try {
    $stmt = $pdo->prepare("SELECT ban_at FROM ip_bans WHERE ip_address = ? LIMIT 1");
    $stmt->execute([$userIp]);
    if ($stmt->fetch()) {
        // IP is banned. Stop all processing.
        http_response_code(403); // Forbidden
        $pageTitle = '登入';
        include __DIR__ . '/../templates/header.php';
        echo '<div class="card"><h2>登入</h2><div class="msg">您的 IP 位址已被系統鎖定，請聯絡管理員。</div></div>';
        include __DIR__ . '/../templates/footer.php';
        exit; // 停止執行
    }
} catch (PDOException $e) {
    if ($e->getCode() !== '42S02') {
         error_log("IP ban check failed: " . $e->getMessage());
    }
    // else: ip_bans table doesn't exist, skip check.
}

// 切換帳號
$wantChangeAccount =
    (isset($_GET['change_id'])) ||
    ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'change_id');

if ($wantChangeAccount) {
    unset($_SESSION['pending_login_id']);
    unset($_SESSION['VerifyCode']);
    $step = 1;
}

// 若已有學號，直接進入 Step 2
if (!empty($_SESSION['pending_login_id'])) {
    $step = 2;
    $inputStudentId = $_SESSION['pending_login_id'];
    if (empty($_SESSION['VerifyCode'])) {
        $_SESSION['VerifyCode'] = gen_code(6);
    }
}

// 📍 改：檢查學號是否存在（對應 users.student_id 欄位）
function account_exists(PDO $pdo, string $student_id): bool {
    $stmt = $pdo->prepare('SELECT id FROM users WHERE student_id = ? LIMIT 1');
    $stmt->execute([$student_id]);
    return (bool)$stmt->fetchColumn();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  /*
      // 🟩 CSRF 驗證（先檢查 session 與輸入是否存在，避免 warning）
    $csrf_input = $_POST['csrf'] ?? '';

     // 🟩 新增：CSRF Token 過期檢查（例如 10 分鐘 = 600 秒）
    $csrf_lifetime = 600; // token 有效時間（秒）
    if (isset($_SESSION['csrf_time']) && (time() - $_SESSION['csrf_time']) > $csrf_lifetime) {
        unset($_SESSION['csrf']);
        unset($_SESSION['csrf_time']);
        header('Location: ./error_csrf.php?type=expired');
    }


    if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf']) || !is_string($csrf_input) || !hash_equals($_SESSION['csrf'], $csrf_input)) {
        // 建議：在正式環境不要直接 die()，改為顯示錯誤頁或 redirect
       header('Location: ./error_csrf.php?type=invalid');   
    }

    // 🟩 CSRF 通過後建議銷毀（一次性 token）
    // 🟩 通過驗證後清除舊 token
    unset($_SESSION['csrf']);
    unset($_SESSION['csrf_time']);
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
    $_SESSION['csrf_time'] = time();
*/
    $action = $_POST['action'] ?? '';

    if ($action === 'check_id') {
        // Step 1：輸入學號
        $student_id = trim($_POST['student_id'] ?? '');
        $inputStudentId = $student_id;
       if ($student_id === '') { // ✅  只要不是空的就可以
            $msg = '請輸入學號或教師帳號';
            $step = 1;
        } else {
            $user = get_user_by_id($pdo, $student_id); // lib/auth.php

            if ($user === false) {
                $msg = '查無此學號，請確認是否正確。';
                $step = 1;
            } elseif (is_account_locked($pdo, (int)$user['id'])) { // lib/auth.php
                $msg = '此帳號因錯誤次數過多已被暫時鎖定，請稍後再試。';
                $step = 1; // 停在第一步
            } else {
                // 學號存在且未鎖定，進入下一步
                $_SESSION['pending_login_id'] = $student_id;
                $_SESSION['VerifyCode'] = gen_code(6); // 產生驗證碼
                $step = 2;
                // $inputStudentId 已在前面賦值
            }
        }
    }
    elseif ($action === 'submit_password') {
        // Step 2：密碼 + CAPTCHA
        $student_id = $_SESSION['pending_login_id'] ?? ($_POST['id_locked'] ?? '');
        $pwd        = $_POST['password'] ?? '';
        $codeInput  = strtoupper(trim($_POST['captcha'] ?? ''));
        $codeSess   = strtoupper($_SESSION['VerifyCode'] ?? '');

        $user = ($student_id !== '') ? get_user_by_id($pdo, $student_id) : false; // lib/auth.php
        $userId = $user ? (int)$user['id'] : null;

                // 基本檢查
        if ($student_id === '') {
            $msg = '連線階段已過期或無效，請重新輸入學號。';
            unset($_SESSION['pending_login_id']);
            $step = 1;
        } elseif ($user === false) {
             $msg = '查無此學號，請返回上一步重新輸入。';
             unset($_SESSION['pending_login_id']);
             $step = 1;
        } elseif ($userId !== null && is_account_locked($pdo, $userId)) { // lib/auth.php - 再次檢查鎖定
            $msg = '此帳號已被鎖定，請稍後再試。';
            $step = 2; // 留在第二步
            $inputStudentId = $student_id;
            $_SESSION['VerifyCode'] = gen_code(6); // 刷新驗證碼
        }
        else{
           if ($codeSess === '' || !hash_equals($codeSess, $codeInput)) {
                // --- CAPTCHA 錯誤 ---
                $msg = '驗證碼錯誤，請再試一次。';
                // log_login($pdo, $userId, $student_id, false); // 通常 CAPTCHA 錯誤不記錄為登入失敗
                $step = 2;
                $inputStudentId = $student_id;
                $_SESSION['VerifyCode'] = gen_code(6); // 刷新驗證碼
            }
            else {
                // --- CAPTCHA 正確，驗證密碼 ---
                unset($_SESSION['VerifyCode']); // 驗證碼用過即清除

                // 使用 lib/auth.php 的 login_password_only 驗證密碼
                $loginResult = login_password_only($pdo, $student_id, $pwd);

                if ($loginResult) {
                    // 登入成功：重置 session id 防止 fixation
                    //session_regenerate_id(true); // 🟩 新增：重要

                    $loggedInUser = $loginResult;
    
                    // --- 🛑 除錯開始：請暫時加入這幾行 ---
                    $userId = $loggedInUser['id']; // 確保從登入結果拿到正確 ID
    
                    if ($userId !== null) {
                   try {
                        $stmt = $pdo->prepare("
                        UPDATE account_lockouts 
                         SET 
                         unlocked_at = NOW(), 
                         unlock_reason = '登入成功自動解鎖',
                         warp_up = 1
                        WHERE user_id = ? AND warp_up = 0
                      ");
                     $stmt->execute([$userId]);
               } catch (PDOException $e) {
                error_log("解鎖更新失敗: " . $e->getMessage());
               }
              } 
                    // 📍 修改結束

                    unset($_SESSION['pending_login_id']);

                    // 準備 Session 資料
                    $sessionUserData = [
                        'id'         => $loggedInUser['id'],
                        'student_id' => $loggedInUser['student_id'],
                        'email'      => $loggedInUser['email'],
                        'name'       => $loggedInUser['name'],
                         'role'       => $user['role'] ?? 'student',
                    ];

                    // 判斷高風險或首次登入
                    if (($loggedInUser['is_high_risk'] ?? 'N') === 'Y') {
                        if (($loggedInUser['is_first_login'] ?? 'N') === 'Y') {
                            $_SESSION['force_totp_setup_user'] = $sessionUserData;
                            header('Location: ./force_totp_setup.php');
                            exit;
                        } else {
                            $_SESSION['pending_user'] = $sessionUserData;
                            header('Location: ./totp_verify.php');
                            exit;
                        }
                    } else {
                        // 一般使用者直接登入
                        $_SESSION['user'] = $sessionUserData;
                        log_login($pdo, $userId, $student_id, true,'密碼正確');

                        // 🟩 如果未來要實作「記住裝置」，可在此設置 cookie（注意要簽名/HMAC）
                        // setcookie('trusted_device', $signed_value, time()+60*60*24*14, '/', '', true, true);

                        header('Location: ./dashboard.php');
                        exit;
                    }
                } else {
                     // --- 密碼錯誤 (login_password_only 回傳 null) ---
                     // log_login 已在 login_password_only 內部呼叫

                    if ($userId !== null) {
                         $failedAttempts = count_recent_failed_logins($pdo, $userId, LOGIN_BASE_PERIOD); // lib/auth.php
                         
                        if ($failedAttempts >= LOGIN_ATTEMPTS_LIMIT) {
                            $activeLockId = null;     // 目前正在進行中的鎖定 ID
                             // 📍 新增點：查詢目前的鎖定等級
                            $currentLockCount = 0;                                                    
                            // 📍 7. 修改點：鎖定時間固定為常數
                            $newLockDuration = LOCKOUT_DURATION_SECONDS; // 總是鎖 60 秒
                            try {
                                    $stmt = $pdo->prepare("
                                        SELECT id,lockout_count 
                                        FROM account_lockouts 
                                        WHERE student_id = ? AND warp_up = 0                                    
                                        ORDER BY id DESC 
                                        LIMIT 1
                                    ");
                                    $stmt->execute([$student_id]);
                                    $row = $stmt->fetch();

                                    if ($row) {
                                        // 仍在鎖定中(或剛鎖定)，計數器繼承
                                        $activeLockId = $row['id'];
                                        $currentLockCount = (int)$row['lockout_count'];
                                    } else {
                                        // 上次鎖定已過期，或從未鎖過，計數器重設為 0
                                        $currentLockCount = 0;
                                    }
                                
                                  // 📍 新增點：決定新的鎖定等級和時間
                                  $newLockCount = $currentLockCount + 1;
                                  if ($activeLockId) {
                                 // 【情境 A】更新現有鎖定 (延長時間、增加次數)
                                 $pdo->prepare("
                                       UPDATE account_lockouts
                                       SET 
                                           locked_until = DATE_ADD(NOW(), INTERVAL ? SECOND),
                                           locked_at = NOW(),
                                           ip_address = ?,
                                           lockout_count = ?,
                                           unlocked_at = NULL
                                           WHERE id = ?
                                 ")->execute([$newLockDuration, $userIp, $newLockCount, $activeLockId]);
                                } else {
                                // 【情境 B】插入全新鎖定 (因為上次的已經 wrap up 了)
                                // 注意：這要求資料庫 schema 不要在 user_id/student_id 上設 UNIQUE 索引
$pdo->prepare("
                    INSERT INTO account_lockouts 
                    (user_id, student_id, locked_until, ip_address, locked_at, lockout_count, warp_up)
                    VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), ?, NOW(), ?, 0)
                ")->execute([
                    $userId,           // 對應 第1個 ? (user_id)
                    $student_id,       // 對應 第2個 ? (student_id)
                    $newLockDuration,  // 對應 第3個 ? (秒數)
                    $userIp,           // 對應 第4個 ? (ip)
                    $newLockCount      // 對應 第5個 ? (次數)
                ]);
                                }
                                                
                                $msg = "密碼錯誤，且已達嘗試上限，帳號已被暫時鎖定 {$newLockDuration} 秒。";

                                // 🟩 8. 檢查 IP 應不應該被 Ban (保留)
                                   if ($newLockCount >= PERM_LOCK_TRIGGER_COUNT) { 
                                     
                                     try {
                                         // 查詢最近 10 筆「所有」失敗日誌 (不受 60 秒限制)
                                         $stmt_logs = $pdo->prepare("
                                             SELECT ip 
                                             FROM login_logs 
                                             WHERE student_id = ? AND success = 0 AND ip IS NOT NULL
                                             ORDER BY id DESC
                                             LIMIT ?
                                         ");
                                         $stmt_logs->execute([$student_id, PERM_LOCK_LOG_CHECK]); // 10
                                         $recent_failed_ips = $stmt_logs->fetchAll(PDO::FETCH_COLUMN);
                                         //執行你剛剛準備好的資料庫查詢 ($stmt_logs)，然後把所有的查詢結果都拿回來，存放到 $recent_failed_ips 這個變數裡

                                         $failure_count = count($recent_failed_ips); // 實際查到的筆數
                                         
                                         // 確保真的有 10 筆失敗紀錄才檢查
                                         if ($failure_count >= PERM_LOCK_LOG_CHECK) {
                                             $distinct_ips = array_unique($recent_failed_ips);//移除陣列中所有重複的值，只留下獨一無二的值。
                                             $ip_variety_count = count($distinct_ips);//計算陣列中值有幾個項目

                                             if ($ip_variety_count >= PERM_LOCK_IP_VARIETY) {
                                                 // 規則 2：IP 種類 >= 3 -> 永久鎖定「學號」
                                                 $perm_lock_reason = "帳號因 (鎖定 {$newLockCount} 次) 且 (最近 " . PERM_LOCK_LOG_CHECK . " 筆失敗含 {$ip_variety_count} 個 IP) 被永久鎖定。";
                                                 $pdo->prepare("
                                                     UPDATE account_lockouts SET locked_until = '9999-12-31 23:59:59', unlock_reason = ? WHERE user_id = ?
                                                 ")->execute([$perm_lock_reason, $userId]);

                                                 $msg = "此帳號因偵測到異常活動（多次鎖定並由不同 IP 登入），已被系統永久鎖定。請聯繫管理員。";
                                                 $step = 1; // 踢回第一步

                                             } elseif ($ip_variety_count === 1) {
                                                 // 規則 1：10 次都來自同 1 個 IP -> 永久封鎖「IP」
                                                 $ip_to_ban = $distinct_ips[0]; 
                                                 $perm_lock_reason = "IP 因 (對 {$student_id} 失敗 " . PERM_LOCK_LOG_CHECK . " 次) 被永久封鎖。";
                                                 
                                                 $pdo->prepare("
                                                                INSERT INTO ip_bans (ip_address, student_id, reason) 
                                                                VALUES (?, ?, ?)
                                                                ON DUPLICATE KEY UPDATE 
                                                                ban_at = NOW(), 
                                                                student_id = VALUES(student_id), 
                                                                reason = VALUES(reason)
                                                       ")->execute([$ip_to_ban, $student_id, $perm_lock_reason]);

                                                 $msg = "此 IP ({$ip_to_ban}) 因登入失敗次數過多，已被系統永久封鎖。";
                                                 $step = 1; // 踢回第一步
                                             }
                                             // ( else: IP 種類是 2，不觸發規則)
                                         }
                                         // ( else: 失敗紀錄還不到 10 筆，不觸發規則)

                                     } catch (PDOException $e) {
                                         error_log("Failed to check or apply permanent ban for student_id {$student_id}: " . $e->getMessage());
                                     }
                                 } // [END 永久鎖定邏輯]
                                    // 🟩 IP Ban 邏輯結束
                            } catch (PDOException $e) {
                                die("資料庫錯誤代碼: " . $e->getMessage());
                                $msg = '密碼錯誤，請再試一次。（系統記錄鎖定時發生錯誤）';
                            }
                        } else {
                            // 未達到鎖定次數
                            $remaining = LOGIN_ATTEMPTS_LIMIT - $failedAttempts;
                            $msg = "密碼錯誤，請再試一次。剩餘嘗試次數：{$remaining}";
                        }
                    } else {
                        // $userId 是 null
                        $msg = '密碼錯誤，請再試一次。';
                    }

                    // 密碼錯誤，留在 Step 2
                    $step = 2;
                    $inputStudentId = $student_id;
                    $_SESSION['VerifyCode'] = gen_code(6); // 刷新驗證碼
                } // End 密碼錯誤處理
            }


        }
        
        

        
    }
}

$pageTitle = '登入';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2>登入</h2>

  <?php if ($step === 1): ?>
    <!-- Step 1：輸入學號 -->
    <form method="post" action="./login.php" autocomplete="off">
      <input type="hidden" name="action" value="check_id">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
      <div class="row">
        <label>學號</label>
        <input name="student_id" type="text" required
                placeholder="請輸入學號或教師帳號"
               value="<?= htmlspecialchars($inputStudentId) ?>">
      </div>
      <button class="btn" type="submit">下一步</button>
    </form>

    <p class="muted"><a class="link" href="./forgot_password.php">忘記密碼？</a></p>

  <?php elseif ($step === 2): ?>
    <!-- Step 2：密碼 + CAPTCHA -->
    <form method="post" action="./login.php" autocomplete="off" id="loginForm">
      <input type="hidden" name="action" value="submit_password">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">

      <div class="row">
        <label>學號</label>
        <input type="text" value="<?= htmlspecialchars($inputStudentId) ?>" disabled>
        <input type="hidden" name="id_locked" value="<?= htmlspecialchars($inputStudentId) ?>">
        <div class="muted" style="margin-top:4px;">
          <a class="link" href="./login.php?change_id=1">不是你？更換帳號</a>
        </div>
      </div>

      <div class="row">
        <label>密碼</label>
        <div style="position:relative; display:inline-block; width:100%;">
          <input type="password" name="password" id="password" required style="width:100%; padding-right:30px;">
          <button type="button" id="togglePwd"
                  style="position:absolute; right:5px; top:5px; border:none; background:none; cursor:pointer;">
            👁️
          </button>
        </div>
        <div id="capsWarning" style="color:red; display:none; font-size:12px; margin-top:4px;">
          ⚠️ Caps Lock 已開啟
        </div>
      </div>

      <!-- CAPTCHA -->
      <div class="row">
        <label>驗證碼</label>
        <div class="captcha-group">
          <input name="captcha"
                 type="text"
                 inputmode="latin"
                 maxlength="6"
                 pattern="[A-Za-z0-9]{6}"
                 required
                 placeholder="輸入底下代碼"
                 class="captcha-input">
          <div class="captcha-visual">
            <img src="./captcha.php" id="captchaImg" alt="驗證碼" class="captcha-img" width="200" height="60">
            <button type="button" id="refresh-btn" aria-label="換一張" class="icon-btn" onclick="refreshCaptcha()">
              <svg viewBox="0 0 24 24" class="icon">
                <path d="M17.65 6.35A7.95 7.95 0 0 0 12 4a8 8 0 1 0 7.75 6h-2.1A6 6 0 1 1 12 6
                c1.3 0 2.5.42 3.47 1.13L13 9.6h7V2.6l-2.35 2.35z" fill="currentColor"></path>
              </svg>
            </button>
          </div>
        </div>
      </div>

      <button class="btn" type="submit">登入</button>
    </form>

    <p class="muted" style="margin-top:8px;">
      <a class="link" href="./forgot_password.php">忘記密碼？</a>
    </p>
  <?php endif; ?>

  <?php if ($msg): ?>
    <div class="msg"><?= htmlspecialchars($msg) ?></div>
  <?php endif; ?>
</div>

<script>
(function(){
  const pwdInput = document.getElementById('password');
  const toggleBtn = document.getElementById('togglePwd');
  const capsWarning = document.getElementById('capsWarning');

  if (pwdInput && toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      if (pwdInput.type === 'password') {
        pwdInput.type = 'text';
        toggleBtn.textContent = '🙈';
      } else {
        pwdInput.type = 'password';
        toggleBtn.textContent = '👁️';
      }
    });
    const updateCaps = (e) => {
      if (e.getModifierState && e.getModifierState('CapsLock')) {
        capsWarning.style.display = 'block';
      } else {
        capsWarning.style.display = 'none';
      }
    };
    pwdInput.addEventListener('keyup', updateCaps);
    pwdInput.addEventListener('keydown', updateCaps);
  }
})();

function refreshCaptcha(){
  const btn = document.getElementById('refresh-btn');
  const img = document.getElementById('captchaImg');
  if(!img) return;
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
