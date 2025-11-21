<?php
declare(strict_types=1);

/** 忘記密碼模板 */
function tpl_reset_password(string $email, string $resetUrl): array {
  $subject = '重設密碼連結（30 分鐘內有效）';
  $safeUrl = htmlspecialchars($resetUrl, ENT_QUOTES, 'UTF-8');

  $html = <<<HTML
<p>您好 {$email}，</p>
<p>請在 <strong>30 分鐘內</strong> 點擊以下連結重設密碼：</p>
<p><a href="{$safeUrl}">{$safeUrl}</a></p>
<p>若非您本人操作，請忽略本信。</p>
HTML;

  $text = "您好 {$email}：\n請在 30 分鐘內點擊以下連結重設密碼：\n{$resetUrl}\n若非您本人操作，請忽略本信。";
  return [$subject, $html, $text];
}

/** TOTP 驗證碼模板（如需） */
function tpl_totp_code(string $email, string $code): array {
  $subject = '你的一次性驗證碼（TOTP）';
  $html = <<<HTML
<p>您好 {$email}，</p>
<p>你的一次性驗證碼為：</p>
<h2 style="letter-spacing:2px;">{$code}</h2>
<p>此驗證碼將在 30 秒後失效，請盡速輸入。</p>
HTML;
  $text = "您好 {$email}：\n你的驗證碼：{$code}\n30 秒後失效。";
  return [$subject, $html, $text];
}

/** 新裝置登入提醒模板（如需） */
function tpl_login_alert(string $email, string $ip, string $when, string $reviewUrl): array {
  $subject = '新裝置登入提示';
  $safeUrl = htmlspecialchars($reviewUrl, ENT_QUOTES, 'UTF-8');
  $html = <<<HTML
<p>您好 {$email}，</p>
<p>我們在 {$when} 偵測到自 IP <code>{$ip}</code> 的登入。</p>
<p>若非本人操作，請立即重設密碼並點此檢視活動：<a href="{$safeUrl}">{$safeUrl}</a></p>
HTML;
  $text = "您好 {$email}：\n{$when} 有從 IP {$ip} 的登入。\n如非本人，請重設密碼並檢視活動：{$reviewUrl}";
  return [$subject, $html, $text];
}
