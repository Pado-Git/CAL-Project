<?php
// Directory Traversal 취약점 - 의도적으로 취약하게 작성됨
header('Content-Type: text/html; charset=utf-8');

$file = $_GET['file'] ?? '';
$content = '';

if ($file) {
    // 취약한 코드: Directory Traversal 가능
    $filepath = "/var/www/html/" . $file;
    if (file_exists($filepath)) {
        $content = file_get_contents($filepath);
    } else {
        $content = "파일을 찾을 수 없습니다: " . $filepath;
    }
}
?>
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <title>파일 보기</title>
    <style>
        body {
            font-family: Arial;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }

        .content {
            background: #f5f5f5;
            padding: 20px;
            font-family: monospace;
            white-space: pre-wrap;
            border: 1px solid #ddd;
        }

        .warning {
            background: #fff3cd;
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
    <h1>파일 내용</h1>

    <div class="warning">
        <strong>요청된 파일 경로:</strong><br>
        <code><?php echo htmlspecialchars($filepath ?? ''); ?></code>
    </div>

    <div class="content">
        <?php echo htmlspecialchars($content); ?>
    </div>

    <a href="index.html">← 돌아가기</a>
</body>

</html>