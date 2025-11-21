<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

// 用本機的 MariaDB socket（你查到的是這條）
$socket = '/run/mysqld/mysqld.sock';

try {
    // 改重點：改成用 unix_socket，而不是 host
    $dsn = "mysql:unix_socket={$socket};dbname={$dbname};charset=utf8mb4";

    $pdo = new PDO($dsn, $dbuser, $dbpwd, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    exit('資料庫連線失敗：' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
}
