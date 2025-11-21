<?php
declare(strict_types=1);

// 顯示 PHP 錯誤（方便排錯）
error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once __DIR__ . '/../vendor/autoload.php'; // public/ 往上一層的 vendor
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$defaultTo   = isset($_GET['to']) ? $_GET['to'] : 'u11106236@o365.ttu.edu.tw';
$defaultFrom = 'i4010@ttu.edu.tw'; // 建議用學校允許的寄件位址
$send        = ($_SERVER['REQUEST_METHOD'] === 'POST');

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html>
<html lang="zh-Hant">
<meta charset="utf-8">
<title>SMTP 測試（TTU relay）</title>
<style>
  body{font-family:ui-sans-serif,system-ui;max-width:880px;margin:40px auto;padding:0 16px}
  .card{background:#fff;border:1px solid #eee;border-radius:12px;padding:16px 20px;margin:16px 0}
  .ok{color:#0a7a20}.err{color:#b00020}.mono{font-family:ui-monospace,Consolas,monospace;white-space:pre-wrap}
  label{display:block;margin:8px 0 4px} input,textarea{width:100%;padding:8px;border:1px solid #ddd;border-radius:8px}
  button{padding:10px 16px;border:0;border-radius:10px;background:#0ea5e9;color:#fff;cursor:pointer}
</style>
<div class="card">
  <h2>SMTP 測試（smtp.ttu.edu.tw:25）</h2>
  <form method="post">
    <label>收件人 (To)</label>
    <input name="to" type="email" required value="<?=h($defaultTo)?>">

    <label>主旨</label>
    <input name="subject" value="<?=h($_POST['subject'] ?? 'SMTP 測試（TTU relay）')?>">

    <label>內容 (可 HTML)</label>
    <textarea name="body" rows="6"><?=h($_POST['body'] ?? ('這是一封從 '.gethostbyname(gethostname()).' 寄出的測試信，時間：'.date('Y-m-d H:i:s')))?></textarea>

    <label>寄件人 From（必須是允許的網域）</label>
    <input name="from" value="<?=h($_POST['from'] ?? $defaultFrom)?>">

    <div style="margin-top:12px">
      <button type="submit">送出測試信</button>
    </div>
  </form>
</div>

<?php if ($send):
  $to      = trim($_POST['to']   ?? $defaultTo);
  $subject = trim($_POST['subject'] ?? 'SMTP 測試（TTU relay）');
  $body    = (string)($_POST['body'] ?? '測試信');
  $from    = trim($_POST['from'] ?? $defaultFrom);

  $mail = new PHPMailer(true);
  // 將 Debug 輸出收集到字串後再顯示在頁面
  $debugBuf = '';
  $mail->SMTPDebug   = 2;
  $mail->Debugoutput = static function($str,$lvl) use (&$debugBuf){ $debugBuf .= $str."\n"; };

  try {
    // === 校內 SMTP relay（無帳密） ===
    $mail->isSMTP();
    $mail->Host       = 'smtp.ttu.edu.tw';
    $mail->Port       = 25;
    $mail->SMTPAuth   = false;                 // relay 不驗證
    // $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // 若改用 587 再開
    // $mail->Port       = 587;                               // 若改用 STARTTLS

    $mail->CharSet    = 'UTF-8';
    $mail->Hostname   = gethostname() ?: 'auth2fa.local'; // HELO 名稱
    $mail->Helo       = $mail->Hostname;

    // From 與 Envelope-From（Return-Path）
    $mail->setFrom($from, 'TTU-Auth');
    $mail->Sender = $from;

    $mail->addAddress($to);
    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body    = $body;
    $mail->AltBody = strip_tags($body);

    $mail->send();
    echo '<div class="card ok"><b>✅ 寄送成功</b></div>';
  } catch (Exception $e) {
    echo '<div class="card err"><b>❌ 寄送失敗：</b> '.h($mail->ErrorInfo ?: $e->getMessage()).'</div>';
  }

  echo '<div class="card"><h3>SMTP 除錯輸出</h3><div class="mono">'.h($debugBuf).'</div></div>';
endif; 


// === 新增：寄出綁定信的小工具 ===
if (!function_exists('send_mail_o365_bind')) {
  function send_mail_o365_bind(string $to, string $link): void {
    $mail = new PHPMailer(true);
    $mail->isSMTP(); $mail->Host='smtp.ttu.edu.tw'; $mail->Port=25; $mail->SMTPAuth=false;
    $mail->CharSet='UTF-8';
    $mail->setFrom('no-reply@ttu.edu.tw', 'TTU-Auth');
    $mail->addAddress($to);
    $mail->Subject='請完成 Microsoft Authenticator 綁定';
    $mail->isHTML(true);
    $mail->Body = "
      <p>您好，請點擊下方按鈕前往安全頁面完成 <b>Microsoft Authenticator</b> 綁定：</p>
      <p><a href='$link' style='padding:10px 16px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none'>前往綁定</a></p>
      <p>若按鈕無法開啟，請複製下列連結：</p>
      <p><code>$link</code></p>
      <p>此連結 24 小時內有效，且僅可使用一次。</p>";
    $mail->AltBody = "請於 24 小時內開啟：$link";
    $mail->send();
  }
}
?>

<div class="card">
  <h3>快速檢查</h3>
  <ol>
    <li>確認這支檔案在：<code>auth2fa/public/test_smtp.php</code>，且 <code>../vendor/autoload.php</code> 存在。</li>
    <li>伺服器能連 <code>smtp.ttu.edu.tw:25</code>：
      <div class="mono">telnet smtp.ttu.edu.tw 25<br>或 nc -vz smtp.ttu.edu.tw 25</div>
    </li>
    <li>From 必須是學校允許 relay 的地址，否則會被 550/553 拒絕（如：Sender address rejected）。</li>
  </ol>
</div>
