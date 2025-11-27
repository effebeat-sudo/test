<?php
$config = require __DIR__ . '/../config.php';

function encryptValue(string $plaintext): string
{
    global $config;
    $key = hash('sha256', $config['encryption_key'], true);
    $iv = random_bytes(16);
    $ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    $payload = base64_encode($iv . $ciphertext);
    return $payload;
}

function decryptValue(?string $payload): string
{
    if ($payload === null || $payload === '') {
        return '';
    }
    global $config;
    $key = hash('sha256', $config['encryption_key'], true);
    $raw = base64_decode($payload, true);
    if ($raw === false || strlen($raw) < 17) {
        return '';
    }
    $iv = substr($raw, 0, 16);
    $ciphertext = substr($raw, 16);
    $plaintext = openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $plaintext !== false ? $plaintext : '';
}
