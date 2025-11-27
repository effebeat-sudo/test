<?php
// Application configuration
return [
    'db' => [
        'host' => 'localhost',
        'dbname' => 'vault_app',
        'user' => 'root',
        'pass' => 'password',
        'charset' => 'utf8mb4',
    ],
    // Change this key in production. Store it securely.
    'encryption_key' => 'change_this_demo_key_please',
    // OTP settings (in seconds)
    'otp_ttl' => 300,
];
