<?php
$config = require __DIR__ . '/../config.php';

$baseDsn = static fn(string $host): string => sprintf('mysql:host=%s;dbname=%s;charset=%s', $host, $config['db']['dbname'], $config['db']['charset']);

$attempts = [];
$initialHost = $config['db']['host'];
$initialPass = $config['db']['pass'];

// First attempt with provided credentials
$attempts[] = ['dsn' => $baseDsn($initialHost), 'user' => $config['db']['user'], 'pass' => $initialPass];

// If host is localhost, try the loopback IP as an alternative (common in Docker/MAMP setups)
if ($initialHost === 'localhost') {
    $attempts[] = ['dsn' => $baseDsn('127.0.0.1'), 'user' => $config['db']['user'], 'pass' => $initialPass];
}

// If a password is provided for root, try also with empty password as a fallback
if ($config['db']['user'] === 'root' && $initialPass !== '') {
    $attempts[] = ['dsn' => $baseDsn($initialHost), 'user' => 'root', 'pass' => ''];
    if ($initialHost === 'localhost') {
        $attempts[] = ['dsn' => $baseDsn('127.0.0.1'), 'user' => 'root', 'pass' => ''];
    }
}

$lastException = null;
foreach ($attempts as $attempt) {
    try {
        $pdo = new PDO($attempt['dsn'], $attempt['user'], $attempt['pass'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $lastException = null;
        break;
    } catch (PDOException $e) {
        $lastException = $e;
    }
}

if (!isset($pdo)) {
    $hint = ' Verifica le credenziali in config.php o le variabili d\'ambiente DB_HOST/DB_NAME/DB_USER/DB_PASSWORD.';
    if ($config['db']['user'] === 'root') {
        $hint .= ' Se usi MySQL locale senza password, lascia DB_PASSWORD vuoto o rimuovi password nel config.';
    }
    if ($initialHost === 'localhost') {
        $hint .= ' In alcuni ambienti può servire usare 127.0.0.1 al posto di localhost.';
    }
    die('Database connection failed: ' . htmlspecialchars($lastException?->getMessage() ?? 'Unknown error') . $hint);
}