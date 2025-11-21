<?php // templates/footer.php：收尾 main、頁尾、body、html ?>
</main> <!-- 關閉置中主容器 -->
<div id="system-time" class="system-time">系統時間：</div>
<footer class="footer">© <?= date('Y') ?> 校園登入系統 · All rights reserved.</footer>

<!-- 系統時間 JS -->
<script>
function updateTime() {
    const now = new Date(); // 取得目前本地時間

    const yyyy = now.getFullYear();
    const mm   = String(now.getMonth() + 1).padStart(2, '0'); // 月份0到11，需加1，並確保兩位數
    const dd   = String(now.getDate()).padStart(2, '0'); 

    let hh   = now.getHours()
    const mi   = String(now.getMinutes()).padStart(2, '0');
    const ss   = String(now.getSeconds()).padStart(2, '0');

     // 星期陣列（0 = 星期日）
    const weekdays = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'];
    const weekday = weekdays[now.getDay()]; // 取得今天是星期幾

    let period;
    if(hh < 12){
        period = "上午";
    }
    else{
        period = "下午";
    }

    if(hh > 12){
        hh = hh - 12;
    }
    else if(hh === 0){
        hh = 12
    }
    
    hh = String(hh).padStart(2, '0');

    // 找到頁面中id="system-time"的元素
    const el = document.getElementById("system-time");

    // 元素存在
    if (el) {
        el.textContent = `系統時間：${yyyy}年${mm}月${dd}日 ${period} ${hh}:${mi}:${ss} | ${weekday}`;
    }
}

updateTime(); // 頁面載入時立即更新一次
setInterval(updateTime, 1000); // 每秒執行一次
</script>

</body>
</html>
