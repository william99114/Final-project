<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) session_start();

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/totp.php';

// +++ 增加：檢查帳號是否被鎖定 (從 login.php 移入) +++
/**
 * @param PDO $pdo
 * @param int $user_id 使用者 ID
 * @return bool True if locked, False otherwise
 */
/**
 * 檢查帳號是否「目前」處於鎖定狀態 - (修正版：使用 SQL NOW() 避免時區問題)
 */
function is_account_locked(PDO $pdo, int $user_id): bool {
    try {
        $stmt = $pdo->prepare("
            SELECT 1
            FROM account_lockouts
            WHERE user_id = ?
              AND unlocked_at IS NULL                      -- 尚未解鎖
              AND (locked_until IS NULL OR locked_until > NOW()) -- 永久鎖定或尚未到期
            LIMIT 1
        ");
        $stmt->execute([$user_id]);
        return (bool)$stmt->fetchColumn(); // 如果找到有效鎖定紀錄，回傳 true
    } catch (PDOException $e) {
        error_log("Failed to check account lock status for user ID {$user_id}: " . $e->getMessage());
        return false; // 查詢失敗時，預設為不鎖定
    }
}
// +++ END 增加 +++

/**
 * 計算最近失敗次數 (滑動窗口) - 修正版
 *
 * @param int $userId
 * @param int $periodInSeconds (這會接收 login.php 傳來的 60)
 * @return int
 */
function count_recent_failed_logins(PDO $pdo, int $userId, int $periodInSeconds): int {
    try {
        // 關鍵：AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
        // 這確保只計算 $periodInSeconds (60秒) 內的失敗紀錄，這才是正確的滑動窗口邏輯。
        $stmt = $pdo->prepare("
            SELECT COUNT(id) 
            FROM login_logs 
            WHERE user_id = ? 
              AND success = 0 
              AND login_time > DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->execute([$userId, $periodInSeconds]);
        
        return (int)$stmt->fetchColumn();

    } catch (PDOException $e) {
        error_log("Failed to count recent failed logins for user ID {$userId}: " . $e->getMessage());
        return 0; // 發生錯誤時回傳 0
    }
}
// +++ 增加：取得使用者資料 (從 login.php 移入) +++
/**
 * @param PDO $pdo
 * @param string $student_id
 * @return array|false User data array or false if not found
 */
function get_user_by_id(PDO $pdo, string $student_id) {
    // --- 程式碼從 login.php 移入 ---
    $stmt = $pdo->prepare('
        SELECT id, student_id, email, name, password_hash, is_high_risk, is_first_login, role
        FROM users
        WHERE student_id = ?
        LIMIT 1
    ');
    $stmt->execute([$student_id]);
    return $stmt->fetch(PDO::FETCH_ASSOC); // 回傳 fetch 結果 (可能是 false)
    // --- END ---
}
// +++ END 增加 +++

/**
 * 寫登入紀錄到 login_logs
 * 📍 第二個參數改成 $account（可放學號或 email）
 *    若你的 login_logs 欄位仍叫 email，短期先把學號寫進該欄位即可。
 */
function log_login(PDO $pdo, ?int $userId, ?string $account, bool $success,?string $reason = null): void {
    // 開錯誤模式（避免靜默失敗）
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $ip = $_SERVER['REMOTE_ADDR']     ?? null;
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;

    // $account 這裡就是學號
    $studentId = $account;

    // 用 user_id 補上 email（若 userId 存在）
    $email = null;
    if ($userId) {
        $stmtE = $pdo->prepare('SELECT email FROM users WHERE id = ? LIMIT 1');
        $stmtE->execute([$userId]);
        $email = $stmtE->fetchColumn() ?: null;
    }

    $stmt = $pdo->prepare('
        INSERT INTO login_logs (user_id, student_id, email, ip, user_agent, success, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ');
    $stmt->execute([
        $userId,
        $studentId,
        $email,
        $ip,
        $ua,
        $success ? 1 : 0,
        $reason
    ]);
}


/**（保留）註冊：仍以 email 為主，若未使用可略過 */
function register_user(PDO $pdo, string $email, string $name, string $password, string $password2): array {
    $email = trim($email);
    $name  = trim($name);

    if (!preg_match('/^[A-Za-z0-9._%+-]+@o365\.ttu\.edu\.tw$/', $email)) {
        return [false, '必須使用學校信箱（@o365.ttu.edu.tw）'];
    }
    if ($password !== $password2) {
        return [false, '兩次輸入的密碼不一致'];
    }
    if (strlen($password) < 6) {
        return [false, '密碼至少 6 碼'];
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare('INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)');
        $stmt->execute([$email, $name, $hash]);
        $userId = (int)$pdo->lastInsertId();

        $secret = totp_generate_secret();
        $stmt2 = $pdo->prepare('INSERT INTO totp_secrets (user_id, secret) VALUES (?, ?)');
        $stmt2->execute([$userId, $secret]);

        $pdo->commit();
        return [true, null, $userId, $secret];
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        if ($e->getCode() === '23000') return [false, '此信箱已註冊'];
        return [false, '資料庫錯誤'];
    }
}

/**
 * 📍 密碼驗證（以學號登入）
 * 成功回傳 users 整列資料；失敗回傳 false
 */
function login_password_only(PDO $pdo, string $student_id, string $pwd) {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE student_id = ? LIMIT 1');
    $stmt->execute([$student_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // 查無帳號時也記錄一次失敗（account 寫入學號）
        log_login($pdo, null, $student_id, false,'密碼錯誤');
        return false;
    }

    if (!password_verify($pwd, $user['password_hash'])) {
        // 密碼錯誤記錄一次
        log_login($pdo, (int)$user['id'], $student_id, false,'密碼錯誤');
        return false;
    }

    // 成功先不記錄，等真正登入（或 TOTP 通過）再記錄成功
    return $user;
}

/**
 * 📍 進行 TOTP 驗證，通過才正式登入
 * 這裡會以 $_SESSION['pending_user'] 內的 'student_id' 記錄成功登入
 */
function verify_totp_and_login(PDO $pdo, string $code): bool {
    if (!isset($_SESSION['pending_user'])) return false;

    $u = $_SESSION['pending_user']; 

    $stmt = $pdo->prepare('SELECT secret FROM totp_secrets WHERE user_id = ? LIMIT 1');
    $stmt->execute([$u['id']]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        log_login($pdo, $u['id'], $u['email'], false); // <--- 建議補上：沒有密鑰也算失敗
        return false;
    }

    if (totp_verify($row['secret'], $code)) {
        // 正式登入
        $_SESSION['user'] = $u;
        unset($_SESSION['pending_user']);

        // 📍 以學號記錄成功
        $account = $u['student_id'] ?? explode('@', $u['email'])[0];
        log_login($pdo, (int)$u['id'], $account, true,'TOTP驗證成功');
        return true;
    }
    // 失敗紀錄：一樣優先用學號，沒有則切分 Email
    // 這樣既不會因為 Email 太長而報錯，也不會因為沒有學號而存成 NULL
    $account = $u['student_id'] ?? explode('@', $u['email'])[0];
    log_login($pdo, (int)$u['id'], $account, false,'TOTP驗證錯誤');
    return false;
}

/** 登入狀態/資訊/登出 */
function is_logged_in(): bool { return isset($_SESSION['user']); }

function current_user(): ?array { return $_SESSION['user'] ?? null; }

function logout_user(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'] ?? '', $p['secure'] ?? false, $p['httponly'] ?? true);
    }
    session_destroy();
}
