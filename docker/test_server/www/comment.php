<?php
// XSS 취약점 - 의도적으로 취약하게 작성됨
header('Content-Type: text/html; charset=utf-8');

$comment = $_POST['comment'] ?? '';
?>
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <title>댓글 작성 결과</title>
    <style>
        body {
            font-family: Arial;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }

        .comment {
            background: #f0f0f0;
            padding: 15px;
            margin: 20px 0;
            border-left: 4px solid #3498db;
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
    <h1>댓글이 작성되었습니다</h1>

    <div class="warning">
        ⚠️ 이 페이지는 XSS 취약점을 가지고 있습니다. 사용자 입력이 필터링되지 않습니다.
    </div>

    <div class="comment">
        <strong>작성된 댓글:</strong><br><br>
        <!-- 취약한 코드: XSS 가능 - htmlspecialchars 없이 직접 출력 -->
        <?php echo $comment; ?>
    </div>

    <a href="index.html">← 돌아가기</a>
</body>

</html>