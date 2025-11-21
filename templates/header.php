<?php
// 若尚未啟動 session，啟動以便後續讀寫 $_SESSION
if (session_status() === PHP_SESSION_NONE) session_start();

// 如果外部沒先設定 $pageTitle，就預設為「校園登入系統」
$pageTitle  = $pageTitle  ?? '校園登入系統';
// 以 session 判斷是否登入（是否存在 user）
$isLoggedIn = !empty($_SESSION['user']);
// 取使用者名稱（已登入時才有；否則給空字串）
$username   = $isLoggedIn ? ($_SESSION['user']['name'] ?? '') : '';
?>
<!doctype html> <!-- 宣告文件為 HTML5 -->
<html lang="zh-Hant"> <!-- 頁面主要語系為繁體中文 -->
<head>
  <meta charset="utf-8"> <!-- 頁面字元編碼為 UTF-8 -->
  <!-- 以 XSS 安全方式輸出 <title>，顯示每頁的標題 -->
  <title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1"> <!-- 行動裝置 RWD 正確縮放 -->
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+TC:wght@300;400;500;700&display=swap" rel="stylesheet">

  <style>
    /* ===== CSS 變數：統一顏色、圓角、陰影等 ===== */
    :root{
      --bg:#f6f8fb;              /* 頁面背景色（淡灰） */
      --card:#fff;               /* 卡片背景色（白） */
      --text:#111827;            /* 主要文字顏色 */
      --muted:#6b7280;           /* 次要文字顏色 */
      --primary:#2563eb;         /* 主色（藍） */
      --primary-press:#1d4ed8;   /* 主色 hover/active 時更深藍 */
      --border:#e5e7eb;          /* 邊框顏色（淡灰） */
      --ring:#dbeafe;            /* 聚焦時外光暈顏色（淡藍） */
      --shadow:0 10px 30px rgba(16,24,40,.06); /* 卡片陰影 */
      --radius:16px;             /* 卡片圓角 */
    }

    *{ box-sizing:border-box }            /* 寬高計算包含邊框，避免排版超出 */
    html,body{ height:100% }             /* 讓 body 能至少滿高，利於布局 */

    body {
      margin: 0;                         /* 移除預設外距，避免多出捲動 */
      font-family: "Noto Sans TC", "Segoe UI", system-ui, -apple-system, sans-serif; /* 字型族群 Microsoft JhengHei*/
      background-image: url("image/bg1.jpg"); /* 背景圖片 */
      background-size: 100% auto;        /* 不變形、充滿整頁 */
      background-position: 50% 10%;
      /* 置中 */
      background-repeat: no-repeat;  /* 不重複 */
      /*background: var(--bg);*/             /* 頁面背景色 */
      color: var(--text);                /* 文字顏色 */
      line-height: 1.55;                 /* 行高，提升可讀性 */
      min-height: 100vh;                 /* 最小高度滿螢幕（不足時 footer 仍在下方） */
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      background: rgba(207, 204, 204, 0.5);  /* 淡淡暗色遮罩，讓卡片更亮 */
      backdrop-filter: blur(8px);       /* 背景模糊，超級專業 */
      z-index: 0;
    }

    /* 讓所有前景元素浮在背景模糊層上 */
    body > * {
        position: relative;
        z-index: 1;
    }

    /* ===== 頂部導覽列樣式 ===== */
    .topbar{
      max-width:1200px;                  /* 置中容器最大寬度 */
      margin:0 auto;                     /* 左右置中 */
      padding:50px 24px 0;               /* 上方與左右留白 */
      display:flex;                      /* 使用 Flex 佈局 */
      align-items:center;                /* 垂直置中導覽內容 */
      justify-content:space-between;     /* 左右兩側分散對齊 */
    }
    .brand{                               /* 左上品牌名稱 */
      font-weight:800;                    /* 加粗 */
      letter-spacing:.02em;               /* 字距略增 */
      color:#0f172a;                      /* 深色文字 */
       position: absolute;
    left: 50%;
    transform: translateX(-50%);
    }
    .nav{ display:flex; gap:16px }        /* 右側導覽連結橫排，連結間距 16px */
    .nav a{
      color:var(--primary);               /* 連結文字使用主色 */
      text-decoration:none;               /* 取消底線 */
      font-weight:600;                    /* 稍微加粗 */
      padding:8px 10px;                   /* 內距，提升點擊面積 */
      border-radius:8px;                  /* 輕微圓角 */
    }
    .nav a:hover,
    .nav a.active{                        /* 滑過或為目前頁面時 */
      background:rgba(37,99,235,.08);     /* 淡藍底，當作高亮 */
    }

    .badge{                               /* 使用者問候徽章（登入後顯示） */
      color:#0f172a;
      background:#eef2ff;
      border:1px solid #e0e7ff;
      border-radius:999px;                /* 做成膠囊形狀 */
      padding:5px 10px;
      font-size:12px;
    }

    /* ===== 主內容區容器：置中且靠上 ===== */
    .page {
      margin: 40px auto;                  /* 上下空 40px、左右置中 */
      max-width: 900px;                   /* 主容器寬度上限（不影響卡片最大寬） */
      padding: 0 24px;                    /* 左右留白 */
      display: flex;                      /* 橫向置中卡片 */
      justify-content: center;            /* 水平置中子元素（卡片） */
      /*transform: translateY(-5%);*/  /* 👈 上移 5%（可調整） */
      /* 不設定 align-items，讓內容靠上更符合表單頁視覺 */
    }

    /* ===== 卡片樣式（表單外框） ===== */
    .card {
      background: var(--card);            /* 白底 */
      border: 1px solid var(--border);    /* 淡灰邊框 */
      border-radius: var(--radius);       /* 圓角 */
      box-shadow: var(--shadow);          /* 柔和陰影 */
      width: 100%;                        /* 先撐滿容器寬 */
      max-width: 500px;                   /* 但不超過 500px（你原本喜歡的視覺比例） */
      /*margin-top: 80px;    👈 卡片往下移 */
    }

    @media (min-width:720px){
      .card{ padding:56px 44px }          /* 較寬視窗時，增大內距更舒適 */
    }

    /* ===== 文字排版 ===== */
    .title{      
      text-align: center;                 /* 主標題置中 */        
      font-size:28px;                     /* 主標題大小 */
      font-weight:800;                    /* 粗體 */
      margin:0 0 8px;                     /* 與下方元素留白 8px */
    }
    .subtitle{
      margin:0 0 24px;                    /* 與下方留白 */
      color:var(--muted);                 /* 次要文字色 */
    }
    .muted{ 
      color:var(--muted)                  /* 次要文字色 */   
    }          

    /* ===== 表單列 ===== */
    .row{ margin:16px 0 }                 /* 每一列上下間距 16px */
    .row label{
      display:block;                      /* label 獨占一行 */
      font-size:14px;                     /* 字級 */
      color:var(--muted);                 /* 顏色偏淡 */
      margin-bottom:8px;                  /* 與輸入框距離 */
    }

    /* 輸入框（通用） */
    .input,
    input[type="text"], input[type="email"], input[type="password"]{
      width:100%;                         /* 滿寬 */
      height:44px;                        /* 高度 */
      font-size:15px;                     /* 字體大小 */
      padding:0 14px;                     /* 左右內距 */
      border:1px solid var(--border);     /* 邊框 */
      border-radius:10px;                 /* 圓角 */
      outline:0;                          /* 取消預設 outline */
      background:#fff;                    /* 白底 */
      transition:border .15s, box-shadow .15s; /* 聚焦動畫 */
    }
    .input:focus,
    input[type="text"]:focus, input[type="email"]:focus, input[type="password"]:focus{
      border-color:var(--primary);        /* 聚焦時邊框變藍 */
      box-shadow:0 0 0 4px var(--ring);   /* 顯示淡藍光暈 */
    }

    /* 按鈕（共用） */
    .btn{
      margin:0 auto;
      display:flex;                /* 讓文字在按鈕內置中 */
      align-items:center;                 /* 垂直置中 */
      justify-content:center;             /* 水平置中 */
      justify-self: center;
      width:200px;
      height:44px;                        /* 高度 */
      padding:0 18px;                     /* 左右內距 */
      border:0;                           /* 無邊框 */
      border-radius:10px;                 /* 圓角 */
      cursor:pointer;                     /* 滑鼠變點擊手勢 */
      font-weight:700;                    /* 粗體 */
      font-size:15px;                     /* 字級 */
    }
    .btn.primary {
      background: #f3f4f6;   /* 灰底 */
      color: #000;           /* 黑字 */
    }
    .btn.primary:hover {
      background: #e0e0e0;   /* 深灰 */
  }

    .btn.block{ width:100% }                                   /* 需要滿寬按鈕可加此類別 */

    /* 連結樣式 */
    .link{ color:var(--primary); text-decoration:none }        /* 藍色、無底線 */
    .link:hover{ text-decoration:underline }                   /* 滑過呈現底線 */

    /* 訊息框（錯誤/成功） */
    .msg{
      margin:12px 0 0;                   /* 與上方留白 */
      padding:12px;                      /* 內距 */
      border-radius:10px;                /* 圓角 */
      border:1px solid #fecaca;          /* 淡紅邊框 */
      background:#fff5f5;                /* 淡紅底 */
      color:#991b1b;                     /* 深紅字 */
    }
    .msg.ok{
      border-color:#a7f3d0;              /* 淡綠邊框 */
      background:#ecfdf5;                /* 淡綠底 */
      color:#065f46;                     /* 深綠字（成功） */
    }

    .system-time{
      margin-bottom:8px;
      color:#000;
      margin-top:12px;
      font-size:12px;
      text-align:center;
    }

    /* ===== 頁尾樣式 ===== */
    .footer{
       color: #6b7280;
    background: transparent;
    
      backdrop-filter: blur(4px);
      border-radius: 6px;
      padding: 4px 10px;

      display: block;      /* 讓 margin auto 生效 */
      /*max-width: 300px;    /* 建議用小值，不需要 900px */
      width: fit-content;
      margin: 0 auto;      /* ✔ 置中成功 */

      text-align: center;  
      font-size: 12px;
    }


    /* —— OAuth 區塊：兩顆按鈕置中且與輸入框同寬 —— */
    .oauth { margin-top: 12px; }
    .oauth form { margin: 0; }               /* 移除表單外距，按鈕緊貼排列 */
    .oauth .btn {
      display: block;                        /* 讓按鈕獨佔一行 */
      width: 100%;                           /* 滿寬（= 和輸入框一樣寬） */
      margin: 8px 0;                         /* 上下間距 */
      background: #f3f4f6;                   /* 灰底，和你現在風格一致 */
      color: #111827;
    }
    .oauth .btn:hover {
  background: #e0e0e0 !important;
}


    /* === CAPTCHA 美化 === */
.captcha-group{
  display:flex; align-items:center; gap:12px; flex-wrap:wrap;
}
.captcha-input{
  padding:10px 12px; border:1px solid var(--border); border-radius:10px;
  font-size:16px; line-height:1; width:170px; outline:none;
  transition:border-color .2s, box-shadow .2s;
}
.captcha-input:focus{
  border-color:var(--primary); box-shadow:0 0 0 3px var(--ring);
}

/* 原本 .captcha-visual 可能是 position:relative; 之類的，改成 flex */
.captcha-visual{
  display: inline-flex;
  align-items: center;
  gap: 10px;           /* 圖片與按鈕的間距 */
}

/* 圖片維持原高 */
.captcha-img{
  width: 240px !important;
  height: 80px !important;
  max-width: none !important;   /* 防止 img{max-width:100%} 縮小 */
  object-fit: contain;
  display: block;
  image-rendering: auto;
}

/* 把按鈕從絕對定位改成一般按鈕 */
.icon-btn{
  position: static;            /* 取消 absolute */
  width: 36px; height: 36px;
  min-width: 36px; min-height: 36px;
  display:flex; align-items:center; justify-content:center;
  border: 1px solid var(--border);
  border-radius: 9999px;
  background:#fff;
  color:#111827;
  cursor:pointer;
  transition: background-color .2s, box-shadow .2s, transform .1s;
}
.icon-btn:hover{ background:#fff; box-shadow:0 2px 10px rgba(0,0,0,.06); }
.icon-btn:active{ transform:scale(.97); }
.icon{ width:20px; height:20px; }

/* 若你之前有 .icon-btn.spin .icon 的動畫，保留即可 */
.icon-btn.spin .icon{ animation:spin .6s linear infinite; }
@keyframes spin{ from{transform:rotate(0)} to{transform:rotate(360deg)} }




  </style>
</head>
<body> <!-- <body> 開始 -->
<header class="topbar"> <!-- 頂部導覽列 -->
  <div class="brand">校園登入系統</div> <!-- 左側品牌名稱 -->
  <nav class="nav"> <!-- 右側導覽連結 -->
    <?php if ($isLoggedIn): ?>
    <a href="/auth2fa/public/dashboard.php">主頁</a>
    <a href="/auth2fa/public/logout.php">登出</a>
<?php else: ?>
    <!-- 不顯示登入連結 -->
<?php endif; ?>


    
  </nav>
</header>

<!-- 主內容容器：卡片會置中顯示、視覺靠上 -->
<main class="page">
