<?php
declare(strict_types=1);
require_once __DIR__ . '/../middleware/auth_required.php'; // 確保已登入

// 取得當前使用者資料
$user = current_user();
$role = $user['role'] ?? 'student'; // 預設為學生

// 根據身分設定頁面標題
$pageTitle = ($role === 'teacher') ? '教師後台' : '學生主頁';

include __DIR__ . '/../templates/header.php';
?>

<div class="card">
  <h2>歡迎，<?= htmlspecialchars($user['name']) ?></h2>
  <p class="muted">
    您的帳號：<?= htmlspecialchars($user['student_id'] ?? $user['email']) ?>
    <span class="badge" style="margin-left: 8px; font-size: 0.9em;">
      <?= ($role === 'teacher') ? '教師' : '學生' ?>
    </span>
  </p>

  <hr style="margin: 24px 0; border: 0; border-top: 1px solid #eee;">

  <?php if ($role === 'teacher'): ?>

      <div style="background-color: #eff6ff; padding: 20px; border-radius: 12px; border: 1px solid #bfdbfe;">
          <h3 style="color: #1e40af; margin-top:0; display:flex; align-items:center; gap:8px;">
            <span>👨‍🏫</span> 教師控制台
          </h3>
          <p style="color: #1e3a8a; margin-bottom: 16px;">您可以管理課程與查看學生狀況。</p>
          
          <div style="display: grid; gap: 12px;">
            <a href="#" class="btn" style="background:#3b82f6; color:white; text-decoration:none;">查看修課學生名單</a>
            <a href="#" class="btn" style="background:#3b82f6; color:white; text-decoration:none;">輸入學期成績</a>
            <a href="#" class="btn" style="background:#3b82f6; color:white; text-decoration:none;">課程管理</a>
          </div>
      </div>

  <?php else: ?>

      <div style="background-color: #f0fdf4; padding: 20px; border-radius: 12px; border: 1px solid #bbf7d0;">
          <h3 style="color: #166534; margin-top:0; display:flex; align-items:center; gap:8px;">
            <span>🎓</span> 學生資訊
          </h3>
          <p style="color: #14532d; margin-bottom: 16px;">查詢您的修課與成績紀錄。</p>

          <div style="display: grid; gap: 12px;">
            <a href="#" class="btn" style="background:#22c55e; color:white; text-decoration:none;">查詢個人課表</a>
            <a href="#" class="btn" style="background:#22c55e; color:white; text-decoration:none;">查詢缺曠紀錄</a>
            <a href="#" class="btn" style="background:#22c55e; color:white; text-decoration:none;">歷年成績查詢</a>
          </div>
      </div>

  <?php endif; ?>

</div>

<?php include __DIR__ . '/../templates/footer.php'; ?>