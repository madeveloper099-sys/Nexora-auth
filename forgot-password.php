
<?php
session_start();

$host = "localhost";
$dbname = "nexora_auth";
$username = "root";
$password = "";

$message = "";

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

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = filter_var(trim($_POST["email"] ?? ""), FILTER_VALIDATE_EMAIL);

    if (!$email) {
        $message = "Please enter a valid email address.";
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Same response whether the account exists or not.
        $message = "If this email is registered, a password reset link will be sent.";

        if ($user) {
            $token = bin2hex(random_bytes(32));
            $tokenHash = hash("sha256", $token);

            $stmt = $pdo->prepare(
                "UPDATE users SET reset_token = ?, reset_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?"
            );
            $stmt->execute([$tokenHash, $user["id"]]);

            // Change this URL when you deploy the project online.
            $appUrl = "http://localhost/nexora-auth";
            $resetLink = $appUrl . "/reset-password.php?token=" . urlencode($token);

            $subject = "Nexora Auth - Password Reset";
            $body = "Hello,\n\nUse this link to reset your password:\n\n"
                  . $resetLink
                  . "\n\nThis link expires in 1 hour.";

            $headers = "From: Nexora Auth <no-reply@example.com>";

            // Requires a working mail server configuration.
            mail($email, $subject, $body, $headers);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forgot Password | Nexora Auth</title>

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
        radial-gradient(circle at 15% 20%, #42205c 0, transparent 35%),
        radial-gradient(circle at 85% 80%, #54230f 0, transparent 35%),
        #080808;
}

.card {
    width: 100%;
    max-width: 430px;
    padding: 42px 32px;
    border: 1px solid #ffffff20;
    border-radius: 22px;
    background: #151515dd;
    backdrop-filter: blur(20px);
    box-shadow: 0 25px 80px #0009;
    animation: appear .7s ease;
}

@keyframes appear {
    from { opacity: 0; transform: translateY(25px); }
    to { opacity: 1; transform: translateY(0); }
}

.logo {
    color: #ff7a1a;
    font-size: 27px;
    font-weight: 800;
    margin-bottom: 30px;
}

h1 {
    font-size: 29px;
    margin-bottom: 12px;
}

p {
    color: #aaa;
    line-height: 1.6;
    font-size: 14px;
    margin-bottom: 25px;
}

label {
    display: block;
    margin-bottom: 9px;
    font-size: 13px;
    color: #ddd;
}

input {
    width: 100%;
    padding: 15px;
    background: #222;
    color: white;
    border: 1px solid #383838;
    border-radius: 10px;
    outline: none;
    margin-bottom: 20px;
}

input:focus {
    border-color: #ff7a1a;
    box-shadow: 0 0 0 3px #ff7a1a20;
}

button {
    width: 100%;
    padding: 15px;
    border: 0;
    border-radius: 10px;
    background: linear-gradient(100deg, #ff7a1a, #ff4d00);
    color: white;
    font-weight: bold;
    cursor: pointer;
    transition: .3s;
}

button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px #ff7a1a40;
}

.message {
    padding: 13px;
    margin-bottom: 20px;
    border-radius: 9px;
    background: #242424;
    color: #ffb477;
    font-size: 13px;
    line-height: 1.5;
}

.back {
    display: block;
    text-align: center;
    color: #ff9a50;
    text-decoration: none;
    margin-top: 25px;
    font-size: 14px;
}
</style>
</head>

<body>
<div class="card">

    <div class="logo">NEXORA<span style="color:white">.</span></div>

    <h1>Forgot Password?</h1>

    <p>
        Don't worry. Enter your registered email address
        and we'll send you a password reset link.
    </p>

    <?php if ($message): ?>
        <div class="message">
            <?= htmlspecialchars($message) ?>
        </div>
    <?php endif; ?>

    <form method="POST">
        <label for="email">Email Address</label>

        <input
            type="email"
            id="email"
            name="email"
            placeholder="Enter your registered email"
            required
        >

        <button type="submit">Send Reset Link →</button>
    </form>

    <a class="back" href="index.php">← Back to Login</a>

</div>
</body>
</html>
