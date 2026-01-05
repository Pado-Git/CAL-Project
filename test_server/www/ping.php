<?php
// Command Injection 취약점 - 의도적으로 취약하게 작성됨
header('Content-Type: text/html; charset=utf-8');

$host = $_GET['host'] ?? '';
$output = '';

if ($host) {
    // 취약한 코드: Command Injection 가능
    $command = "ping -c 3 " . $host;
    exec($command, $output);
}
?>
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <title>Ping 결과</title>
    <style>
        body {
            font-family: Arial;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }

        .output {
            background: #2c3e50;
            color: #2ecc71;
            padding: 20px;
            font-family: monospace;
            white-space: pre-wrap;
        }

        .warning {
            background: #ffebee;
            padding: 15px;
            margin: 20px 0;
        }

        a {
            display: inline-block;
            margin: 20px 0;
            color: #3498db;
        }
    </style>
</head>

<body>
    <h1>Ping 결과</h1>

    <div class="warning">
        <strong>실행된 명령어:</strong><br>
        <code><?php echo htmlspecialchars($command ?? ''); ?></code>
    </div>

    <?php if ($output): ?>
        <div class="output">
            <?php echo implode("\n", $output); ?>
        </div>
    <?php endif; ?>

    <a href="index.html">← 돌아가기</a>
</body>

</html>