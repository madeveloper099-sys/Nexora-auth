
<?php
session_start();

/* DATABASE CONFIGURATION */
$host = "localhost";
$dbname = "nexora_auth";
$username = "root";
$dbpassword = "";

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $username,
        $dbpassword,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );
} catch (PDOException $e) {
    die("Database connection failed. Check your database settings.");
}

/* CREATE CSRF TOKEN */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";
$messageType = "";
$activeTab = "login";

/* FORM PROCESSING */
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $activeTab = $_POST['action'] ?? 'login';

    if (
        !isset($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        $message = "Invalid request. Please refresh the page.";
        $messageType = "error";

    } else {

        $email = trim($_POST['email'] ?? "");
        $password = $_POST['password'] ?? "";

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = "Please enter a valid email address.";
            $messageType = "error";

        } elseif ($activeTab === "register") {

            $name = trim($_POST['name'] ?? "");

            if (strlen($name) < 2 || strlen($name) > 100) {
                $message = "Name must contain 2 to 100 characters.";
                $messageType = "error";

            } elseif (strlen($password) < 8) {
                $message = "Password must contain at least 8 characters.";
                $messageType = "error";

            } else {
                $check = $pdo->prepare(
                    "SELECT id FROM users WHERE email = ?"
                );
                $check->execute([$email]);

                if ($check->fetch()) {
                    $message = "This email is already registered.";
                    $messageType = "error";

                } else {
                    $hashedPassword = password_hash(
                        $password,
                        PASSWORD_DEFAULT
                    );

                    $stmt = $pdo->prepare(
                        "INSERT INTO users (name, email, password)
                         VALUES (?, ?, ?)"
                    );

                    $stmt->execute([
                        $name,
                        $email,
                        $hashedPassword
                    ]);

                    $message = "Account created successfully! You can now sign in.";
                    $messageType = "success";
                    $activeTab = "login";
                }
            }

        } elseif ($activeTab === "login") {

            $stmt = $pdo->prepare(
                "SELECT * FROM users WHERE email = ? LIMIT 1"
            );

            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password'])) {

                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];

                header("Location: index.php");
                exit;

            } else {
                $message = "Incorrect email or password.";
                $messageType = "error";
            }
        }
    }
}

/* LOGOUT */
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();

    header("Location: index.php");
    exit;
}

$isLoggedIn = isset($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#08080d">

<title>NEXORA — Authentication</title>

<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --orange: #ff792e;
    --purple: #9857ff;
    --bg: #08080d;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    min-height: 100vh;
    background: var(--bg);
    color: white;
    font-family: 'Inter', sans-serif;
    overflow-x: hidden;
}

body::before,
body::after {
    content: "";
    position: fixed;
    width: 450px;
    height: 450px;
    border-radius: 50%;
    filter: blur(120px);
    opacity: .25;
    pointer-events: none;
    animation: glow 12s ease-in-out infinite alternate;
}

body::before {
    background: var(--orange);
    top: -180px;
    left: -150px;
}

body::after {
    background: var(--purple);
    bottom: -180px;
    right: -150px;
    animation-delay: -5s;
}

@keyframes glow {
    to {
        transform: translate(120px, 100px) scale(1.3);
    }
}

#particles {
    position: fixed;
    inset: 0;
    overflow: hidden;
    pointer-events: none;
}

.particle {
    position: absolute;
    bottom: -20px;
    width: 3px;
    height: 3px;
    background: #ff9a63;
    border-radius: 50%;
    box-shadow: 0 0 12px var(--orange);
    animation: rise linear infinite;
}

@keyframes rise {
    from {
        transform: translateY(0);
        opacity: 0;
    }
    20% { opacity: .8; }
    to {
        transform: translateY(-110vh);
        opacity: 0;
    }
}

.wrapper {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 30px 18px;
    position: relative;
    z-index: 2;
}

.card {
    width: 100%;
    max-width: 440px;
    padding: 40px;
    background: rgba(22, 20, 30, .82);
    border: 1px solid rgba(255,255,255,.11);
    border-radius: 25px;
    backdrop-filter: blur(25px);
    box-shadow: 0 30px 100px rgba(0,0,0,.5);
    position: relative;
    overflow: hidden;
    animation: enter .8s ease both;
}

@keyframes enter {
    from {
        opacity: 0;
        transform: translateY(35px) scale(.96);
    }
    to {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
}

.card::before {
    content: "";
    position: absolute;
    top: 0;
    left: 10%;
    width: 80%;
    height: 2px;
    background: linear-gradient(
        90deg, transparent, var(--orange), var(--purple), transparent
    );
    box-shadow: 0 0 20px var(--orange);
}

.logo {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
    margin-bottom: 32px;
}

.logo-icon {
    width: 38px;
    height: 38px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    font-size: 21px;
    font-weight: 800;
    background: linear-gradient(135deg, var(--orange), var(--purple));
    box-shadow: 0 0 25px #ff792e50;
}

.logo h2 {
    font-size: 20px;
    letter-spacing: 3px;
}

.logo span {
    color: var(--orange);
}

.heading {
    text-align: center;
    margin-bottom: 28px;
}

.eyebrow {
    color: var(--orange);
    font-size: 10px;
    letter-spacing: 4px;
    margin-bottom: 12px;
    font-weight: 700;
}

.heading h1 {
    font-size: 30px;
    letter-spacing: -1px;
    margin-bottom: 10px;
}

.heading p {
    color: #92909c;
    font-size: 12px;
    line-height: 1.7;
}

.alert {
    padding: 13px;
    margin-bottom: 18px;
    border-radius: 10px;
    font-size: 11px;
    line-height: 1.6;
}

.error {
    color: #ff9999;
    background: #ff454510;
    border: 1px solid #ff454530;
}

.success {
    color: #8df2b2;
    background: #36d77c10;
    border: 1px solid #36d77c30;
}

.field {
    margin-bottom: 20px;
}

.field label {
    display: block;
    color: #d7d5df;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    margin-bottom: 10px;
}

.input-wrap {
    position: relative;
}

.input-wrap input {
    width: 100%;
    height: 52px;
    padding: 0 45px 0 15px;
    background: rgba(255,255,255,.04);
    border: 1px solid rgba(255,255,255,.1);
    border-radius: 11px;
    color: white;
    outline: none;
    font-size: 12px;
    transition: .3s;
}

.input-wrap input:focus {
    border-color: var(--orange);
    box-shadow: 0 0 0 4px #ff792e15;
}

.input-wrap input::placeholder {
    color: #696775;
}

.input-icon {
    position: absolute;
    right: 15px;
    top: 50%;
    transform: translateY(-50%);
    color: #9995a5;
    pointer-events: none;
}

.eye {
    position: absolute;
    right: 13px;
    top: 50%;
    transform: translateY(-50%);
    border: 0;
    background: transparent;
    color: #aaa;
    cursor: pointer;
}

.options {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin: 20px 0;
    font-size: 10px;
}

.remember {
    display: flex;
    gap: 8px;
    align-items: center;
    color: #aaa;
}

.remember input {
    accent-color: var(--orange);
}

a {
    color: var(--orange);
    text-decoration: none;
}

a:hover {
    color: #ffb17f;
}

.submit-btn {
    width: 100%;
    height: 53px;
    border: none;
    border-radius: 11px;
    background: linear-gradient(100deg, var(--orange), var(--purple));
    color: white;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 1px;
    cursor: pointer;
    transition: .3s;
    box-shadow: 0 8px 30px #ff792e25;
}

.submit-btn:hover {
    transform: translateY(-3px);
    box-shadow: 0 12px 35px #ff792e45;
}

.submit-btn:active {
    transform: scale(.98);
}

.switch {
    text-align: center;
    margin-top: 28px;
    color: #92909c;
    font-size: 11px;
}

.footer {
    text-align: center;
    margin-top: 28px;
    color: #65616e;
    font-size: 9px;
    letter-spacing: 2px;
}

.dashboard {
    text-align: center;
}

.dashboard h1 {
    font-size: 29px;
    margin-bottom: 15px;
}

.dashboard p {
    color: #aaa;
    font-size: 13px;
    line-height: 1.8;
    margin-bottom: 25px;
}

@media(max-width: 480px) {
    .card {
        padding: 30px 22px;
    }

    .heading h1 {
        font-size: 26px;
    }
}

@media(prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: .01ms !important;
    }
}
</style>
</head>

<body>

<div id="particles"></div>

<main class="wrapper">

<section class="card" id="card">

    <div class="logo">
        <div class="logo-icon">N</div>
        <h2>NEXO<span>RA</span></h2>
    </div>

    <?php if ($isLoggedIn): ?>

        <div class="dashboard">
            <div class="eyebrow">AUTHENTICATION SUCCESSFUL</div>

            <h1>Welcome back!</h1>

            <p>
                Hello, <?= htmlspecialchars($_SESSION['user_name'], ENT_QUOTES, 'UTF-8') ?>.<br>
                You are successfully logged into NEXORA.
            </p>

            <a class="submit-btn"
               style="display:grid;place-items:center"
               href="?logout=1">
                LOG OUT
            </a>
        </div>

    <?php else: ?>

        <div class="heading">
            <div class="eyebrow">WELCOME TO NEXORA</div>

            <h1>
                <?= $activeTab === "register" ? "Create your account." : "Access your world." ?>
            </h1>

            <p>
                <?= $activeTab === "register"
                    ? "Join us and start your journey."
                    : "Enter your credentials to continue." ?>
            </p>
        </div>

        <?php if ($message): ?>
            <div class="alert <?= htmlspecialchars($messageType) ?>">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="index.php">

            <input type="hidden" name="csrf_token"
                   value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

            <input type="hidden" name="action"
                   value="<?= $activeTab === "register" ? "register" : "login" ?>">

            <?php if ($activeTab === "register"): ?>
                <div class="field">
                    <label for="name">FULL NAME</label>
                    <div class="input-wrap">
                        <input type="text" id="name" name="name"
                               placeholder="Your full name"
                               maxlength="100" required>
                        <span class="input-icon">✦</span>
                    </div>
                </div>
            <?php endif; ?>

            <div class="field">
                <label for="email">EMAIL ADDRESS</label>

                <div class="input-wrap">
                    <input type="email" id="email" name="email"
                           placeholder="name@example.com"
                           autocomplete="email" required>

                    <span class="input-icon">✉</span>
                </div>
            </div>

            <div class="field">
                <label for="password">PASSWORD</label>

                <div class="input-wrap">
                    <input type="password" id="password" name="password"
                           placeholder="Minimum 8 characters"
                           minlength="8"
                           autocomplete="<?= $activeTab === "register" ? "new-password" : "current-password" ?>"
                           required>

                    <button type="button" class="eye"
                            id="togglePassword"
                            aria-label="Show password">◉</button>
                </div>
            </div>

            <?php if ($activeTab === "login"): ?>
                <div class="options">
                    <label class="remember">
                        <input type="checkbox" name="remember">
                        Remember me
                    </label>

                    <a href="mailto:support@example.com">Need help?</a>
                </div>
            <?php endif; ?>

            <button type="submit" class="submit-btn">
                <?= $activeTab === "register" ? "CREATE ACCOUNT →" : "SIGN IN TO NEXORA →" ?>
            </button>

            <a href="forgot-password.php">
    Forgot Password?
</a>

        </form>

        <div class="switch">
            <?php if ($activeTab === "register"): ?>
                Already have an account?
                <a href="index.php">Sign in</a>
            <?php else: ?>
                New to Nexora?
                <a href="?register=1">Create account</a>
            <?php endif; ?>
        </div>

    <?php endif; ?>

    <div class="footer">
        SECURE ACCESS · NEXORA 2026
    </div>

</section>
</main>

<script>
// Animated background particles
const container = document.getElementById("particles");

for (let i = 0; i < 45; i++) {
    const particle = document.createElement("span");

    particle.className = "particle";
    particle.style.left = Math.random() * 100 + "%";
    particle.style.animationDuration = (7 + Math.random() * 13) + "s";
    particle.style.animationDelay = (-Math.random() * 15) + "s";

    container.appendChild(particle);
}

// Mouse-following light effect
const card = document.getElementById("card");

card.addEventListener("pointermove", (e) => {
    const rect = card.getBoundingClientRect();

    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    card.style.background = `
        radial-gradient(
            circle at ${x}px ${y}px,
            rgba(255,122,46,.12),
            rgba(22,20,30,.92) 50%
        )
    `;
});

card.addEventListener("pointerleave", () => {
    card.style.background = "rgba(22,20,30,.82)";
});

// Show and hide password
const toggle = document.getElementById("togglePassword");
const password = document.getElementById("password");

if (toggle && password) {
    toggle.addEventListener("click", () => {
        const show = password.type === "password";

        password.type = show ? "text" : "password";
        toggle.textContent = show ? "◎" : "◉";
        toggle.setAttribute(
            "aria-label",
            show ? "Hide password" : "Show password"
        );
    });
}

// Registration page selection
const params = new URLSearchParams(window.location.search);

if (params.has("register") && !window.location.search.includes("logout")) {
    const form = document.querySelector("form");

    if (form && !form.querySelector('[name="name"]')) {
        window.location.replace("index.php?register=1");
    }
}
</script>

</body>
</html>
m.
