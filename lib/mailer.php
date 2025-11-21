<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;

/**
 * 寄出綁定 Magic Link
 * @return array [bool $ok, string $error]  // $ok=false 時會帶錯誤
 */
function send_mail_o365_bind(string $to, string $link): array {
  $mail = new PHPMailer(true);
  $error = '';

  // 收集 SMTP 對話（除錯用）
  $debugBuf = '';
  $mail->SMTPDebug   = 2;
  $mail->Debugoutput = static function ($str, $lvl) use (&$debugBuf) { $debugBuf .= $str . "\n"; };

  try {
    // === 跟 test_smtp.php 一樣的 TTU relay 設定 ===
    $mail->isSMTP();
    $mail->Host       = 'smtp.ttu.edu.tw';
    $mail->Port       = 25;
    $mail->SMTPAuth   = false;
    $mail->CharSet    = 'UTF-8';
    $mail->Hostname   = gethostname() ?: 'auth2fa.local';
    $mail->Helo       = $mail->Hostname;

    // 用可被 relay 的寄件位址（你測試可用的是 i4010@ttu.edu.tw）
    $from = 'i4010@ttu.edu.tw';
    $mail->setFrom($from, 'TTU-Auth');
    $mail->Sender = $from; // Envelope-From

    $mail->addAddress($to);
    $mail->isHTML(true);
    $mail->Subject = '請完成 Microsoft Authenticator 綁定';
    $mail->Body = "
      <p>您好，請點擊下方按鈕前往安全頁面完成 <b>Microsoft Authenticator</b> 綁定：</p>
      <p><a href='$link' style='padding:10px 16px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none'>前往綁定</a></p>
      <p>若按鈕無法開啟，請複製以下連結：</p>
      <p><code>$link</code></p>
      <p>此連結 24 小時內有效，且僅可使用一次。</p>";
    $mail->AltBody = "請於 24 小時內開啟：$link";

    $ok = $mail->send();
    if (!$ok) {
      $error = trim(($mail->ErrorInfo ?? '') . "\n" . $debugBuf);
    }
    return [$ok, $error];

  } catch (\Throwable $e) {
    $error = $e->getMessage() . "\n" . $debugBuf;
    error_log('send_mail_o365_bind failed: ' . $error);
    return [false, $error];
  }
}
