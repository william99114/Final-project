<?php
declare(strict_types=1);
require_once __DIR__ . '/../config/db.php';
$now = $pdo->query('SELECT NOW()')->fetchColumn();
echo $now ? "DB OK, time = {$now}" : 'DB FAIL';
