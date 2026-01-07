<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/mail.php'; // Inclusione corretta di mail.php

$composerAutoload = __DIR__ . '/../vendor/autoload.php';
if (file_exists($composerAutoload)) {
    require_once $composerAutoload;
}

use PHPMailer\PHPMailer\Exception as MailException;
use PHPMailer\PHPMailer\PHPMailer;
use Throwable; 

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ----------------------------------------------------------------------------------
// FUNZIONI DI GESTIONE UTENTI E AUTENTICAZIONE
// ----------------------------------------------------------------------------------

/**
 * Verifica rigorosa del login.
 * Se la sessione manca o è incompleta (causa degli errori htmlspecialchars null),
 * forza il logout e reindirizza al login.
 */
function requireLogin(): void
{
    // 1. Controllo base: esiste l'ID utente?
    if (empty($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }

    // 2. Controllo Integrità: Esistono Email e Ruolo?
    // Questo previene l'errore "Passing null to parameter #1" nelle pagine
    if (!isset($_SESSION['email']) || !isset($_SESSION['role'])) {
        // La sessione è corrotta o parziale: distruggila e vai al login
        logout(); 
        header('Location: login.php?error=session_expired');
        exit;
    }

    // 3. Controllo Timeout inattività
    enforceSessionTimeout();
}

function enforceSessionTimeout(): void
{
    global $pdo;
    $timeoutSeconds = getSessionTimeoutMinutes($pdo) * 60;

    if (isset($_SESSION['last_activity']) && (time() - (int)$_SESSION['last_activity'] > $timeoutSeconds)) {
        logout(); // Pulisce la sessione
        header('Location: login.php?timeout=1');
        exit;
    }

    $_SESSION['last_activity'] = time();
}

function logout(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        // Se si sta terminando un'impersonificazione, non distruggere la sessione
        if (isImpersonating()) {
            stopImpersonation($GLOBALS['pdo']); // Torna all'utente originale
        } else {
            // Logout completo
            $_SESSION = []; // Svuota l'array
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            session_destroy();
        }
    }
}

// ----------------------------------------------------------------------------------
// ALTRE FUNZIONI DI SUPPORTO (Invariate ma incluse per completezza)
// ----------------------------------------------------------------------------------

function getSetting(PDO $pdo, string $name): ?string
{
    static $cache = [];
    if (array_key_exists($name, $cache)) {
        return $cache[$name];
    }
    try {
        $stmt = $pdo->prepare('SELECT value FROM app_settings WHERE name = ? LIMIT 1');
        $stmt->execute([$name]);
        $row = $stmt->fetch();
        $cache[$name] = $row ? $row['value'] : null;
        return $cache[$name];
    } catch (Throwable $e) {
        return null;
    }
}

function setSetting(PDO $pdo, string $name, string $value): bool
{
    try {
        $stmt = $pdo->prepare('INSERT INTO app_settings (name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)');
        $stmt->execute([$name, $value]);
        return true;
    } catch (Throwable $e) {
        return false;
    }
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

function isPasswordComplex(string $password): bool
{
    return strlen($password) >= 6
        && preg_match('/[A-Za-z]/', $password)
        && preg_match('/\d/', $password)
        && preg_match('/[^A-Za-z0-9]/', $password);
}

function clearOtp(PDO $pdo, int $userId): void
{
    $stmt = $pdo->prepare('UPDATE users SET otp_hash = NULL, otp_expires_at = NULL WHERE id = ?');
    $stmt->execute([$userId]);
}

function establishSession(array $user): void
{
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['email'] = $user['email'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['last_activity'] = time();
}

function initiateLogin(PDO $pdo, string $email, string $password): ?array
{
    $user = getUserByEmail($pdo, $email);
    
    if (!$user || !password_verify($password, $user['password_hash'])) {
        return null;
    }
    
    // Controllo Sospensione
    if ((int)($user['is_suspended'] ?? 0) === 1) {
        return ['suspended' => true];
    }
    
    if (!isOtpEnabled($pdo)) {
        clearOtp($pdo, $user['id']);
        establishSession($user);
        unset($_SESSION['pending_user_id']);
        return ['require_otp' => false, 'user_id' => $user['id']];
    }

    // Logica OTP
    $config = $GLOBALS['config'] ?? require __DIR__ . '/../config.php';
    $otpTtlSeconds = $config['otp_ttl'] ?? 300;
    $otp = (string)random_int(100000, 999999);
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);
    $expires = (new DateTimeImmutable('now'))->modify('+' . $otpTtlSeconds . ' seconds')->format('Y-m-d H:i:s');

    $stmt = $pdo->prepare('UPDATE users SET otp_hash = ?, otp_expires_at = ? WHERE id = ?');
    $stmt->execute([$otpHash, $expires, $user['id']]);

    if (!sendOtpEmail($pdo, $user['email'], $otp)) {
        file_put_contents(__DIR__ . '/../otp_log.txt', sprintf("OTP delivery to %s failed at %s\n", $user['email'], date('c')), FILE_APPEND);
    }

    $_SESSION['pending_user_id'] = $user['id'];
    return ['require_otp' => true, 'user_id' => $user['id']];
}

function verifyOtp(PDO $pdo, int $userId, string $otp): bool
{
    $user = getUserById($pdo, $userId);
    if (!$user) return false;

    if (!isOtpEnabled($pdo)) {
        clearOtp($pdo, $user['id']);
        establishSession($user);
        unset($_SESSION['pending_user_id']);
        return true;
    }

    if (empty($user['otp_hash']) || empty($user['otp_expires_at'])) {
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

    establishSession($user);
    unset($_SESSION['pending_user_id']);
    clearOtp($pdo, $userId);
    return true;
}

function isImpersonating(): bool
{
    return isset($_SESSION['impersonator_id']);
}

function impersonateUser(PDO $pdo, int $targetUserId): bool
{
    if (($_SESSION['role'] ?? '') !== 'superuser') return false;

    $target = getUserById($pdo, $targetUserId);
    if (!$target) return false;

    if (($target['role'] ?? '') === 'superuser') return false;
    if ((int)($target['is_suspended'] ?? 0) === 1) return false; 

    if (!isImpersonating()) {
        $_SESSION['impersonator_id'] = $_SESSION['user_id'];
        $_SESSION['impersonator_email'] = $_SESSION['email'];
        $_SESSION['impersonator_role'] = $_SESSION['role'];
    }

    $_SESSION['user_id'] = $target['id'];
    $_SESSION['email'] = $target['email'];
    $_SESSION['role'] = $target['role'];
    $_SESSION['last_activity'] = time();
    return true;
}

function stopImpersonation(PDO $pdo): bool
{
    if (!isImpersonating()) return false;

    $originalId = (int)$_SESSION['impersonator_id'];
    $original = getUserById($pdo, $originalId);
    if (!$original) {
        // Se l'utente originale non esiste più, logout completo
        $_SESSION = [];
        session_destroy();
        return false;
    }

    $_SESSION['user_id'] = $original['id'];
    $_SESSION['email'] = $original['email'];
    $_SESSION['role'] = $original['role'];
    $_SESSION['last_activity'] = time();
    
    unset($_SESSION['impersonator_id'], $_SESSION['impersonator_email'], $_SESSION['impersonator_role']);
    return true;
}

function requireRole(string $requiredRole): void
{
    requireLogin();
    $current = $_SESSION['role'] ?? 'user';
    if (roleLevel($current) < roleLevel($requiredRole)) {
        http_response_code(403);
        echo 'Access denied';
        exit;
    }
}

function currentUser(PDO $pdo): ?array
{
    static $cache = null;
    if ($cache !== null) return $cache;
    if (!isset($_SESSION['user_id'])) return null;
    $cache = getUserById($pdo, (int)$_SESSION['user_id']);
    return $cache;
}

function getSessionTimeoutMinutes(PDO $pdo): int
{
    $value = getSetting($pdo, 'session_timeout_minutes');
    $minutes = ($value !== null) ? (int)$value : 30;
    return max(5, $minutes);
}

function setSessionTimeoutMinutes(PDO $pdo, int $minutes): bool
{
    if ($minutes < 5) $minutes = 5;
    return setSetting($pdo, 'session_timeout_minutes', (string)$minutes);
}

function isOtpEnabled(PDO $pdo): bool
{
    $value = getSetting($pdo, 'otp_enabled');
    return $value === null ? true : ($value !== '0');
}

function setOtpEnabled(PDO $pdo, bool $enabled): bool
{
    return setSetting($pdo, 'otp_enabled', $enabled ? '1' : '0');
}