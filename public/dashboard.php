<?php
declare(strict_types=1);
require_once __DIR__ . '/../middleware/auth_required.php';
$user = current_user();

$pageTitle = '主頁';
include __DIR__ . '/../templates/header.php';
?>
<div class="card">
  <h2>歡迎，<?=htmlspecialchars($user['student_id'])?></h2>
  <p>您的帳號（學校信箱）：<?=htmlspecialchars($user['email'])?></p>
  <p><a class="link" href="./logout.php">登出</a></p>
</div>
<?php include __DIR__ . '/../templates/footer.php'; ?>
