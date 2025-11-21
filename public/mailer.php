<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;

/**
 * 寄出綁定 Microsoft Authenticator 的 Magic Link 郵件
 *
 * @param string $to     收件者信箱
 * @param string $link   綁定用的一次性連結（24hr 有效）
 * @param array  $meta   其他資訊：
 *   - userType: 'local' | 'cross'  (預設 'local')
 *   - school:   string|null         (跨校可帶)
 *   - studentId:string|null         (跨校可帶)
 *   - debug:    bool                (true 時輸出 SMTP Debug)
 *
 * @return array [bool $ok, string $error]
 */
function send_mail_o365_bind(string $to, string $link, array $meta = []): array {
  $mail = new PHPMailer(true);
  $error = '';

  // 參數
  $userType  = ($meta['userType'] ?? 'local') === 'cross' ? 'cross' : 'local';
  $school    = trim((string)($meta['school'] ?? ''));
  $studentId = trim((string)($meta['studentId'] ?? ''));
  $debug     = (bool)($meta['debug'] ?? false);

  // 轉義避免 XSS/HTML 注入
  $safeLink   = htmlspecialchars($link,   ENT_QUOTES, 'UTF-8');
  $safeSchool = htmlspecialchars($school, ENT_QUOTES, 'UTF-8');
  $safeSid    = htmlspecialchars($studentId, ENT_QUOTES, 'UTF-8');

  // 主旨與前言（依身分切換）
  if ($userType === 'cross') {
    $subject  = '【跨校學生】請完成帳號驗證與 Microsoft Authenticator 綁定';
    $headline = '您是以 <b>跨校學生</b> 身分註冊。';
    $extra    = '';
    if ($safeSchool !== '' || $safeSid !== '') {
      $extra = '<p style="margin:6px 0 0;color:#374151;">'
             . ($safeSchool !== '' ? '就讀學校：'.$safeSchool.'<br>' : '')
             . ($safeSid    !== '' ? '學號：'.$safeSid : '')
             . '</p>';
    }
  } else {
    $subject  = '【本校學生】請完成 Microsoft Authenticator 綁定';
    $headline = '您是以 <b>本校學生</b> 身分註冊（需使用 @o365.ttu.edu.tw）。';
    $extra    = '';
  }

  // 是否開啟 debug
  $debugBuf = '';
  $mail->SMTPDebug   = $debug ? 2 : 0;
  $mail->Debugoutput = static function ($str, $lvl) use (&$debugBuf) { $debugBuf .= $str . "\n"; };

  try {
    // === TTU 郵件 relay 設定 ===
    $mail->isSMTP();
    $mail->Host     = 'smtp.ttu.edu.tw';
    $mail->Port     = 25;
    $mail->SMTPAuth = false;
    $mail->CharSet  = 'UTF-8';
    $mail->Hostname = gethostname() ?: 'auth2fa.local';
    $mail->Helo     = $mail->Hostname;

    // 寄件者
    $from = 'i4010@ttu.edu.tw';
    $mail->setFrom($from, '校園登入系統');
    $mail->Sender = $from;

    // 收件者
    $mail->addAddress($to);

    // 內容
    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body = "
      <div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,'Noto Sans TC',Arial,'Microsoft JhengHei',sans-serif;font-size:15px;color:#111827;line-height:1.6\">
        <p>您好：</p>
        <p>{$headline}{$extra}</p>
        <p>請點擊下方按鈕前往安全頁面完成 <b>Microsoft Authenticator</b> 綁定：</p>
        <p>
          <a href=\"{$safeLink}\"
             style=\"display:inline-block;padding:10px 16px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none\">
            前往綁定
          </a>
        </p>
        <p style=\"margin:10px 0 0\">若按鈕無法開啟，請複製以下連結：</p>
        <p><code style=\"word-break:break-all\">{$safeLink}</code></p>
        <p style=\"color:#6b7280\">此連結 24 小時內有效，且僅可使用一次。</p>
      </div>";
    $mail->AltBody = "您好：\n\n"
                   . ($userType === 'cross' ? "【跨校學生註冊】\n" : "【本校學生註冊】\n")
                   . ($safeSchool !== '' ? "就讀學校：{$school}\n" : '')
                   . ($safeSid    !== '' ? "學號：{$studentId}\n" : '')
                   . "請於 24 小時內開啟以下連結完成綁定：\n{$link}\n";

    // 寄送
    $ok = $mail->send();
    if (!$ok) {
      $error = trim(($mail->ErrorInfo ?? '') . ($debug ? "\n".$debugBuf : ''));
    }
    return [$ok, $error];

  } catch (\Throwable $e) {
    $error = $e->getMessage() . ($debug ? "\n".$debugBuf : '');
    error_log('send_mail_o365_bind failed: ' . $error);
    return [false, $error];
  }
}
