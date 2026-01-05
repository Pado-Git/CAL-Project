<?php
// SQL Injection 취약점 - 의도적으로 취약하게 작성됨
header('Content-Type: text/html; charset=utf-8');

$username = $_GET['username'] ?? '';

// 취약한 코드: SQL Injection 가능
$db = new SQLite3('/tmp/test.db');

// 테이블 생성 (없으면)
$db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)');
$db->exec("INSERT OR IGNORE INTO users (id, username, password, email) VALUES (1, 'admin', 'admin123', 'admin@test.com')");
$db->exec("INSERT OR IGNORE INTO users (id, username, password, email) VALUES (2, 'user', 'user123', 'user@test.com')");

// 취약한 쿼리 - 사용자 입력을 직접 삽입
$query = "SELECT * FROM users WHERE username = '$username'";
$result = $db->query($query);

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>검색 결과</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #3498db; color: white; }
        .warning { background: #ffebee; padding: 15px; margin: 20px 0; }
        a { display: inline-block; margin: 20px 0; color: #3498db; }
    </style>
</head>
<body>
    <h1>검색 결과</h1>
    <div class="warning">
        <strong>실행된 쿼리:</strong><br>
        <code><?php echo htmlspecialchars($query); ?></code>
    </div>

    <?php if ($result): ?>
        <table>
            <tr>
                <th>ID</th>
                <th>사용자명</th>
                <th>비밀번호</th>
                <th>이메일</th>
            </tr>
            <?php while ($row = $result->fetchArray(SQLITE3_ASSOC)): ?>
            <tr>
                <td><?php echo $row['id']; ?></td>
                <td><?php echo $row['username']; ?></td>
                <td><?php echo $row['password']; ?></td>
                <td><?php echo $row['email']; ?></td>
            </tr>
            <?php endwhile; ?>
        </table>
    <?php else: ?>
        <p>결과를 찾을 수 없습니다.</p>
    <?php endif; ?>

    <a href="index.html">← 돌아가기</a>
</body>
</html>
