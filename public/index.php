<?php
session_start();
require_once __DIR__ . '/../config/file';

try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Błąd połączenia z bazą danych.");
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function isLoggedIn() { return isset($_SESSION['user_id']); }
function isAdmin() { return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1; }
function requireLogin() { if (!isLoggedIn()) { header('Location: index.php'); exit(); } }
function requireAdmin() { if (!isAdmin()) { header('Location: index.php?page=dashboard'); exit(); } }
function verifyCsrfToken($token) { return hash_equals($_SESSION['csrf_token'], $token); }

if (!isset($_SESSION['login_attempts'])) { $_SESSION['login_attempts'] = 0; $_SESSION['last_attempt_time'] = 0; }
function canAttemptLogin() {
    if ($_SESSION['login_attempts'] >= 5 && (time() - $_SESSION['last_attempt_time'] < 300)) return false;
    elseif (time() - $_SESSION['last_attempt_time'] >= 300) $_SESSION['login_attempts'] = 0;
    return true;
}
function recordLoginAttempt() { $_SESSION['login_attempts']++; $_SESSION['last_attempt_time'] = time(); }
function secureSessionRegenerate() { session_regenerate_id(true); }

$allowed_pages = ['login','dashboard','wishlist','draw','admin','logout'];
$page = $_GET['page'] ?? (isLoggedIn() ? 'dashboard' : 'login');
if (!in_array($page,$allowed_pages)) $page = isLoggedIn() ? 'dashboard' : 'login';

$container_class = 'login-page';
if ($page=='logout') $container_class = 'logged-out';
elseif (isLoggedIn() && $page!='login') $container_class = 'logged-in';

header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("Referrer-Policy: no-referrer-when-downgrade");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

$loginError = '';
if ($page == 'login' && !isLoggedIn() && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!canAttemptLogin()) {
        $loginError = 'Zbyt wiele prób logowania. Spróbuj ponownie za kilka minut.';
    } elseif (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $loginError = 'Błąd tokenu CSRF. Odśwież stronę i spróbuj ponownie.';
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($password, $user['password'])) {
            secureSessionRegenerate();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = $user['is_admin'];
            $_SESSION['login_attempts'] = 0;
            header('Location: index.php?page=dashboard');
            exit();
        } else {
            recordLoginAttempt();
            $loginError = 'Nieprawidłowa nazwa użytkownika lub hasło!';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Secret Santa</title>
    <link rel="stylesheet" href="css/style.css" />
</head>
<body>
<div class="container <?php echo $container_class; ?>">
    <div class="header">
        <div class="holiday-icon">🎄🎅🎁</div>
        <h1>Kogo obdarujesz prezentem?</h1>
        <p class="subtitle"></p>
    </div>

<?php

if ($page == 'login' && !isLoggedIn()) {
?>
    <?php if (!empty($loginError)): ?><div class="alert alert-error"><?php echo $loginError;?></div><?php endif;?>
    <form method="POST" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>" />
        <div class="form-group">
            <label>Jak Ci na imię?</label>
            <input type="text" name="username" required autofocus />
        </div>
        <div class="form-group">
            <label>Hasło</label>
            <input type="password" name="password" required />
        </div>
        <button type="submit" class="btn">Zapraszam</button>
    </form>
<?php

} elseif ($page == 'dashboard') {
    requireLogin();
    ?>
    <h2>Witaj, <?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES | ENT_HTML5); ?>!</h2>
    <div class="nav-links">
        <a href="index.php?page=wishlist">Moja lista życzeń</a>
        <a href="index.php?page=draw">Losuj osobę</a>
        <?php if (isAdmin()): ?><a href="index.php?page=admin">Panel admina</a><?php endif; ?>
        <a href="index.php?page=logout">Wyloguj</a>
    </div>
    <?php
    $stmt = $pdo->prepare("SELECT d.*, u.username, u.wish_list FROM draws d JOIN users u ON d.drawn_id = u.id WHERE d.drawer_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $draw = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($draw) {
        ?>
        <div class="draw-result">
            <h2>Już wylosowałeś/aś osobę! 🎉</h2>
            <div class="drawn-person"><?php echo htmlspecialchars($draw['username'], ENT_QUOTES | ENT_HTML5); ?></div>
            <?php if ($draw['wish_list']): ?>
                <div class="wish-box">
                    <strong>Lista życzeń:</strong><br>
                    <?php echo nl2br(htmlspecialchars($draw['wish_list'], ENT_QUOTES | ENT_HTML5)); ?>
                </div>
            <?php else: ?>
                <p><em>Ta osoba nie dodała jeszcze swojej listy życzeń</em></p>
            <?php endif; ?>
        </div>
        <?php
    } else {
        echo '<div class="alert alert-info">Jeszcze nie wylosowałeś/aś osoby. Przejdź do zakładki "Losuj osobę"!</div>';
    }
} elseif ($page == 'wishlist') {
    requireLogin();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
            echo '<div class="alert alert-error">Błąd tokenu CSRF. Odśwież stronę i spróbuj ponownie.</div>';
        } else {
            $wish_list = $_POST['wish_list'] ?? '';
            $stmt = $pdo->prepare("UPDATE users SET wish_list = ? WHERE id = ?");
            $stmt->execute([$wish_list, $_SESSION['user_id']]);
            echo '<div class="alert alert-success">Lista życzeń została zaktualizowana!</div>';
        }
    }
    $stmt = $pdo->prepare("SELECT wish_list FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    ?>
    <h2>Moja lista życzeń 📝</h2>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>" />
        <div class="form-group">
            <label>Twój wymarzony prezent:</label>
            <textarea name="wish_list" placeholder="Wpisz swoje życzenia..."><?php echo htmlspecialchars($user['wish_list'], ENT_QUOTES | ENT_HTML5); ?></textarea>
        </div>
        <button type="submit" class="btn">Zapisz listę życzeń</button>
    </form>
    <div class="nav-links">
        <a href="index.php?page=dashboard">← Powrót do panelu</a>
    </div>
    <?php
} elseif ($page == 'draw') {
    requireLogin();
    $stmt = $pdo->prepare("SELECT * FROM draws WHERE drawer_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    if ($stmt->fetch()) {
        echo '<div class="alert alert-error">Już wylosowałeś/aś osobę! Możesz zobaczyć wynik w panelu głównym.</div>';
        echo '<div class="nav-links"><a href="index.php?page=dashboard">← Powrót do panelu</a></div>';
    } else {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $stmt = $pdo->prepare("SELECT id, username, wish_list FROM users WHERE id != ? AND id NOT IN (SELECT drawn_id FROM draws) AND is_admin=0");
            $stmt->execute([$_SESSION['user_id']]);
            $available = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (count($available) > 0) {
                $drawn = $available[array_rand($available)];
                $stmt = $pdo->prepare("INSERT INTO draws (drawer_id, drawn_id) VALUES (?, ?)");
                $stmt->execute([$_SESSION['user_id'], $drawn['id']]);
                ?>
                <div class="draw-result">
                    <h2>Wylosowałeś/aś! 🎉</h2>
                    <div class="drawn-person"><?php echo htmlspecialchars($drawn['username'], ENT_QUOTES | ENT_HTML5); ?></div>
                    <?php if ($drawn['wish_list']): ?>
                        <div class="wish-box">
                            <strong>Lista życzeń:</strong><br>
                            <?php echo nl2br(htmlspecialchars($drawn['wish_list'], ENT_QUOTES | ENT_HTML5)); ?>
                        </div>
                    <?php else: ?>
                        <p><em>Ta osoba nie dodała jeszcze swojej listy życzeń</em></p>
                    <?php endif; ?>
                </div>
                <div class="nav-links">
                    <a href="index.php?page=dashboard">← Powrót do panelu</a>
                </div>
                <?php
            } else {
                echo '<div class="alert alert-error">Brak dostępnych osób do losowania!</div>';
                echo '<div class="nav-links"><a href="index.php?page=dashboard">← Powrót do panelu</a></div>';
            }
        } else {
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users WHERE id != ? AND id NOT IN (SELECT drawn_id FROM draws) AND is_admin=0");
            $stmt->execute([$_SESSION['user_id']]);
            $count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
            ?>
            <h2>Losowanie 🎲</h2>
            <?php if ($count > 0): ?>
                <div class="alert alert-info">
                    Dostępnych osób do losowania: <strong><?php echo $count; ?></strong>
                </div>
                <form method="POST">
                    <button type="submit" class="btn">Losuj osobę!</button>
                </form>
            <?php else: ?>
                <div class="alert alert-error">Brak dostępnych osób do losowania!</div>
            <?php endif; ?>
            <div class="nav-links">
                <a href="index.php?page=dashboard">← Powrót do panelu</a>
            </div>
            <?php
        }
    }
} elseif ($page == 'admin') {
    requireLogin();
    requireAdmin();
    if (isset($_GET['action'], $_GET['id']) && $_GET['action']==='delete') {
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND is_admin = 0");
        $stmt->execute([intval($_GET['id'])]);
        echo '<div class="alert alert-success">Użytkownik został usunięty!</div>';
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_user'])) {
        if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
            echo '<div class="alert alert-error">Błąd tokenu CSRF. Odśwież stronę i spróbuj ponownie.</div>';
        } else {
            $username = $_POST['username'] ?? '';
            $password_raw = $_POST['password'] ?? '';
            if (empty($username) || empty($password_raw)) {
                echo '<div class="alert alert-error">Nazwa użytkownika i hasło są wymagane!</div>';
            } else {
                $password = password_hash($password_raw, PASSWORD_DEFAULT);
                try {
                    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                    $stmt->execute([$username, $password]);
                    echo '<div class="alert alert-success">Użytkownik został dodany!</div>';
                } catch(PDOException $e) {
                    echo '<div class="alert alert-error">Błąd: użytkownik o tej nazwie już istnieje!</div>';
                }
            }
        }
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_draws'])) {
        $pdo->exec("TRUNCATE TABLE draws");
        echo '<div class="alert alert-success">Wszystkie losowania zostały zresetowane!</div>';
    }
?>
    <h2>Panel administratora 👨‍💼</h2>
    <h3>Dodaj nowego użytkownika</h3>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>" />
        <div class="form-group">
            <label>Nazwa użytkownika</label>
            <input type="text" name="username" required />
        </div>
        <div class="form-group">
            <label>Hasło</label>
            <input type="password" name="password" required />
        </div>
        <button type="submit" name="add_user" class="btn">Dodaj użytkownika</button>
    </form>
    <h3 style="margin-top: 30px;">Lista użytkowników</h3>
    <?php
    $stmt = $pdo->query("SELECT * FROM users WHERE is_admin = 0 ORDER BY username");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>
    <ul class="user-list">
        <?php foreach ($users as $user): ?>
            <li class="user-item">
                <div class="user-info">
                    <div class="user-name"><?php echo htmlspecialchars($user['username'], ENT_QUOTES | ENT_HTML5); ?></div>
                    <?php if (!empty($user['email'])): ?>
                        <div class="user-email"><?php echo htmlspecialchars($user['email'], ENT_QUOTES | ENT_HTML5); ?></div>
                    <?php endif; ?>
                </div>
                <a href="index.php?page=admin&action=delete&id=<?php echo intval($user['id']); ?>"
                   onclick="return confirm('Czy na pewno usunąć tego użytkownika?')"
                   class="btn btn-danger btn-small">Usuń</a>
            </li>
        <?php endforeach; ?>
    </ul>
    <form method="POST" style="margin-top: 30px;">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>" />
        <button type="submit" name="reset_draws"
                onclick="return confirm('Czy na pewno zresetować wszystkie losowania?')"
                class="btn btn-secondary">Resetuj wszystkie losowania</button>
    </form>
    <div class="nav-links">
        <a href="index.php?page=dashboard">← Powrót do panelu</a>
    </div>
<?php
} elseif ($page == 'logout') {
    $username = $_SESSION['username'] ?? 'Użytkowniku';
    $_SESSION = array();
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time()-42000, '/', '', true, true);
    }
    session_destroy();
    ?>
    <div class="header">
        <div class="holiday-icon">🎅❄️🎄</div>
        <h1>Do zobaczenia, <?php echo htmlspecialchars($username, ENT_QUOTES | ENT_HTML5); ?>!</h1>
        <p class="subtitle">Wesołych Świąt i udanych prezentów! 🎁</p>
    </div>
    <div class="draw-result" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
        <h2 style="font-size: 28px; margin-bottom: 15px;">🌟 Wesołych Świąt 🌟</h2>
        <p style="font-size: 16px; line-height: 1.6;">
            <br>
            🎄 Niech to będzie cudowny czas spędzony w gronie najbliższych Ci osób! 🎄
        </p>
    </div>
    <div class="nav-links" style="margin-top: 30px;">
        <a href="index.php">← Zaloguj się ponownie</a>
    </div>
    <?php
    echo '</div></body></html>';
    exit();
} else {
    header('Location: index.php?page=dashboard');
    exit();
}
?>

</div>
</body>
</html>
