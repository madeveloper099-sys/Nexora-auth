
<?php
session_start();

$host = "localhost";
$dbname = "nexora_auth";
$username = "root";
$password = "";

$message = "";
$success = false;

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $username,
        $password,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    die("Database connection failed.");
}

$token = $_GET["token"] ?? $_POST["token"] ?? "";
$tokenHash = hash("sha256", $token);

$stmt = $pdo->prepare(
    "SELECT id FROM users WHERE reset_token = ? AND reset_expires > NOW()"
);
$stmt->execute([$tokenHash]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || strlen($token) !== 64) {
    $message = "This reset link is invalid or has expired.";
} elseif ($_SERVER["REQUEST_METHOD"] === "POST") {

    $newPassword = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if (strlen($newPassword) < 8) {
        $message = "Password must be at least 8 characters.";
    } elseif ($newPassword !== $confirmPassword) {
        $message = "Passwords do not match.";
    } else {
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

        $stmt = $pdo->prepare(
            "UPDATE users
             SET password = ?, reset_token = NULL, reset_expires = NULL
             WHERE id = ?"
        );

        $stmt->execute([$hashedPassword, $user["id"]]);

        $success = true;
        $message = "Your password has been reset successfully.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reset Password | Nexora Auth</title>

<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 20px;
    font-family: Arial, sans-serif;
    color: white;
    background:
        radial-gradient(circle at 15% 20%, #42205c, transparent 35%),
        radial-gradient(circle at 85% 80%, #54230f, transparent 35%),
        #080808;
}

.card {
    width: 100%;
    max-width: 430px;
    padding: 40px 32px;
    background: #151515;
    border: 1px solid #ffffff20;
    border-radius: 22px;
    box-shadow: 0 25px 80px #0009;
}

.logo {
    font-size: 26px;
    font-weight: bold;
    color: #ff7a1a;
    margin-bottom: 28px;
}

h1 {
    font-size: 28px;
    margin-bottom: 12px;
}

p {
    color: #aaa;
    margin-bottom: 25px;
    line-height: 1.6;
}

label {
    display: block;
    margin-bottom: 8px;
    color: #ddd;
    font-size: 13px;
}

input {
    width: 100%;
    padding: 14px;
    margin-bottom: 20px;
    border-radius: 9px;
    border: 1px solid #383838;
    background: #222;
    color: white;
    outline: none;
}

input:focus {
    border-color: #ff7a1a;
}

button {
    width: 100%;
    padding: 15px;
    border: none;
    border-radius: 9px;
    color: white;
    background: linear-gradient(100deg, #ff7a1a, #ff4d00);
    font-weight: bold;
    cursor: pointer;
}

.message {
    padding: 13px;
    margin-bottom: 20px;
    background: #252525;
    color: #ffb477;
    border-radius: 9px;
    font-size: 14px;
}

a {
    display: block;
    text-align: center;
    color: #ff9a50;
    text-decoration: none;
    margin-top: 22px;
}
</style>
</head>

<body>
<div class="card">

    <div class="logo">NEXORA.</div>

    <h1>Reset Password</h1>
    <p>Create a new secure password for your account.</p>

    <?php if ($message): ?>
        <div class="message">
            <?= htmlspecialchars($message) ?>
        </div>
    <?php endif; ?>

    <?php if (!$success && $user): ?>
        <form method="POST">
            <input type="hidden" name="token"
                   value="<?= htmlspecialchars($token) ?>">

            <label>New Password</label>
            <input type="password" name="password"
                   placeholder="Minimum 8 characters"
                   minlength="8" required>

            <label>Confirm Password</label>
            <input type="password" name="confirm_password"
                   placeholder="Confirm your password"
                   minlength="8" required>

            <button type="submit">Update Password →</button>
        </form>
    <?php endif; ?>

    <a href="index.php">← Back to Login</a>

</div>
</body>
</html>
