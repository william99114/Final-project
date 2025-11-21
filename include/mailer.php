<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;

/**
 * 建立已設定好的 PHPMailer
 * 優先吃環境變數（SMTP_HOST/USER/PASS/PORT/SECURE/FROM_*）
 * 沒設時回落校內 relay smtp.ttu.edu.tw:25（無帳密）
 */
function make_mailer(): PHPMailer {
  $mail = new PHPMailer(true);

  if (getenv('MAIL_DEBUG') === '1') {
    $mail->SMTPDebug = SMTP::DEBUG_SERVER; // 測試用，上線關掉
  }

  $host      = getenv('SMTP_HOST')   ?: '';
  $smtpUser  = getenv('SMTP_USER')   ?: '';
  $smtpPass  = getenv('SMTP_PASS')   ?: '';
  $portEnv   = getenv('SMTP_PORT')   ?: '';
  $secureEnv = strtolower(getenv('SMTP_SECURE') ?: 'tls'); // tls|ssl
  $fromEmail = getenv('FROM_EMAIL')  ?: ($smtpUser ?: 'no-reply@example.com');
  $fromName  = getenv('FROM_NAME')   ?: '校園登入系統';

  $mail->isSMTP();

  if ($host !== '') {
    // 走外部 SMTP（O365 / Gmail / SendGrid ...）
    $mail->Host       = $host;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtpUser;
    $mail->Password   = $smtpPass;
    if ($secureEnv === 'ssl') {
      $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
      $mail->Port       = (int)($portEnv ?: 465);
    } else {
      $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
      $mail->Port       = (int)($portEnv ?: 587);
    }
  } else {
    // 回落：校內 relay（無帳密）
    $mail->Host       = 'smtp.ttu.edu.tw';
    $mail->Port       = 25;
    $mail->SMTPAuth   = false;
    // From 必須用學校允許的位址
    if ($fromEmail === 'no-reply@example.com') {
      $fromEmail = 'i4010@ttu.edu.tw'; // 改成你可用的學校帳號
    }
  }

  $mail->CharSet = 'UTF-8';
  $mail->setFrom($fromEmail, $fromName);
  return $mail;
}

/** 方便呼叫的共用寄信函式 */
function send_mail(string $to, string $subject, string $html, ?string $text = null): bool {
  $mail = make_mailer();
  $mail->addAddress($to);
  $mail->Subject = $subject;
  $mail->isHTML(true);
  $mail->Body    = $html;
  $mail->AltBody = $text ?: strip_tags($html);
  return $mail->send();
}
