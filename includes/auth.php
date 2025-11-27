<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function getUserByEmail(PDO $pdo, string $email): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    return $user ?: null;
}

function getUserById(PDO $pdo, int $id): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$id]);
    $user = $stmt->fetch();
    return $user ?: null;
}

function roleLevel(string $role): int
{
    return ['user' => 1, 'admin' => 2, 'superuser' => 3][$role] ?? 0;
}

function requireLogin(): void
{
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
}

function requireRole(string $role): void
{
    requireLogin();
    $current = $_SESSION['role'] ?? 'user';
    if (roleLevel($current) < roleLevel($role)) {
        http_response_code(403);
        echo 'Access denied';
        exit;
    }
}

function initiateLogin(PDO $pdo, string $email, string $password): ?int
{
    $user = getUserByEmail($pdo, $email);
    if (!$user || !password_verify($password, $user['password_hash'])) {
        return null;
    }

    $otp = random_int(100000, 999999);
    $otpHash = password_hash((string)$otp, PASSWORD_DEFAULT);
    $expires = (new DateTimeImmutable('now'))->modify('+' . (int)$GLOBALS['config']['otp_ttl'] . ' seconds')->format('Y-m-d H:i:s');

    $stmt = $pdo->prepare('UPDATE users SET otp_hash = ?, otp_expires_at = ? WHERE id = ?');
    $stmt->execute([$otpHash, $expires, $user['id']]);

    $logMessage = sprintf("OTP %s sent to %s at %s\n", $otp, $user['email'], date('c'));
    file_put_contents(__DIR__ . '/../otp_log.txt', $logMessage, FILE_APPEND);

    $_SESSION['pending_user_id'] = $user['id'];
    return $user['id'];
}

function verifyOtp(PDO $pdo, int $userId, string $otp): bool
{
    $user = getUserById($pdo, $userId);
    if (!$user || empty($user['otp_hash']) || empty($user['otp_expires_at'])) {
        return false;
    }

    $now = new DateTimeImmutable('now');
    $expiry = new DateTimeImmutable($user['otp_expires_at']);
    if ($now > $expiry) {
        return false;
    }

    if (!password_verify($otp, $user['otp_hash'])) {
        return false;
    }

    $_SESSION['user_id'] = $user['id'];
    $_SESSION['email'] = $user['email'];
    $_SESSION['role'] = $user['role'];
    unset($_SESSION['pending_user_id']);

    $stmt = $pdo->prepare('UPDATE users SET otp_hash = NULL, otp_expires_at = NULL WHERE id = ?');
    $stmt->execute([$userId]);

    return true;
}

function logout(): void
{
    session_unset();
    session_destroy();
}
