<?php
// forum.php
session_start();

// DB 연결
$host = "localhost";
$user = "root"; // DB 사용자
$pass = "";     // DB 비밀번호
$db   = "forum_db";

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) die("DB 연결 실패: " . $conn->connect_error);
$conn->set_charset("utf8mb4");

// 회원가입 처리
if (isset($_POST['action']) && $_POST['action'] === 'register') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $password);
    if ($stmt->execute()) {
        echo "<p style='color:green;'>회원가입 성공! 로그인 해주세요.</p>";
    } else {
        echo "<p style='color:red;'>회원가입 실패: 이미 존재하는 아이디일 수 있습니다.</p>";
    }
}

// 로그인 처리
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username=?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($id, $hash);
    if ($stmt->num_rows > 0) {
        $stmt->fetch();
        if (password_verify($password, $hash)) {
            $_SESSION['user_id'] = $id;
            $_SESSION['username'] = $username;
        } else {
            echo "<p style='color:red;'>비밀번호가 틀렸습니다.</p>";
        }
    } else {
        echo "<p style='color:red;'>존재하지 않는 사용자입니다.</p>";
    }
}

// 로그아웃 처리
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header("Location: forum.php");
    exit;
}

// 글 작성 처리
if (isset($_POST['action']) && $_POST['action'] === 'write' && isset($_SESSION['user_id'])) {
    $title = $_POST['title'];
    $content = $_POST['content'];
    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)");
    $stmt->bind_param("iss", $user_id, $title, $content);
    $stmt->execute();
    echo "<p style='color:green;'>글 작성 완료!</p>";
}

// 글 보기
$view_post = null;
if (isset($_GET['view'])) {
    $id = intval($_GET['view']);
    $stmt = $conn->prepare("SELECT posts.title, posts.content, users.username, posts.created_at 
                             FROM posts JOIN users ON posts.user_id = users.id 
                             WHERE posts.id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->bind_result($title, $content, $username, $created_at);
    if ($stmt->fetch()) {
        $view_post = ["title"=>$title, "content"=>$content, "username"=>$username, "created_at"=>$created_at];
    }
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>온라인 포럼</title>
</head>
<body>
<h2>온라인 포럼 (단일 파일)</h2>

<?php if (isset($_SESSION['username'])): ?>
    <p>안녕하세요, <?= htmlspecialchars($_SESSION['username']) ?>님! 
       <a href="?action=logout">로그아웃</a></p>

    <!-- 글쓰기 -->
    <h3>글쓰기</h3>
    <form method="POST">
        <input type="hidden" name="action" value="write">
        제목: <input type="text" name="title" required><br>
        내용: <br><textarea name="content" rows="4" cols="40" required></textarea><br>
        <button type="submit">작성</button>
    </form>
<?php else: ?>
    <!-- 로그인 -->
    <h3>로그인</h3>
    <form method="POST">
        <input type="hidden" name="action" value="login">
        아이디: <input type="text" name="username" required><br>
        비밀번호: <input type="password" name="password" required><br>
        <button type="submit">로그인</button>
    </form>

    <!-- 회원가입 -->
    <h3>회원가입</h3>
    <form method="POST">
        <input type="hidden" name="action" value="register">
        아이디: <input type="text" name="username" required><br>
        비밀번호: <input type="password" name="password" required><br>
        <button type="submit">회원가입</button>
    </form>
<?php endif; ?>

<hr>

<?php if ($view_post): ?>
    <!-- 글 보기 -->
    <h3><?= htmlspecialchars($view_post['title']) ?></h3>
    <p><?= nl2br(htmlspecialchars($view_post['content'])) ?></p>
    <p>작성자: <?= htmlspecialchars($view_post['username']) ?> | <?= $view_post['created_at'] ?></p>
    <a href="forum.php">목록으로</a>
<?php else: ?>
    <!-- 글 목록 -->
    <h3>글 목록</h3>
    <?php
    $result = $conn->query("SELECT posts.id, posts.title, users.username, posts.created_at 
                            FROM posts JOIN users ON posts.user_id = users.id 
                            ORDER BY posts.id DESC");
    while ($row = $result->fetch_assoc()) {
        echo "<p><a href='?view=" . $row['id'] . "'>" .
              htmlspecialchars($row['title']) . "</a> - " .
              htmlspecialchars($row['username']) . " (" . $row['created_at'] . ")</p>";
    }
    ?>
<?php endif; ?>

</body>
</html>
