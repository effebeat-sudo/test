<?php
// Application configuration
$envOrDefault = static fn(string $key, string $default = ''): string => getenv($key) !== false ? getenv($key) : $default;

return [
    'db' => [
        'host' => 'localhost',
        'dbname' => 'db6gjnj9qxibxi',
        'user' => 'uwjxvi1avovgv',
        'pass' => '56c27zoi~@11',
        'charset' => 'utf8mb4',
    ],
    // Change this key in production. Store it securely.
    'encryption_key' => $envOrDefault('ENCRYPTION_KEY', 'change_this_demo_key_please'),
    // OTP settings (in seconds)
    'otp_ttl' => (int)$envOrDefault('OTP_TTL', '300'),
    'mail' => [
        'from_email' => $envOrDefault('MAIL_FROM_EMAIL', 'otp@effebit.it'),
        'from_name' => $envOrDefault('MAIL_FROM_NAME', 'OTP'),
        'host' => $envOrDefault('MAIL_HOST', 'c1101617.sgvps.net'),
        'port' => (int)$envOrDefault('MAIL_PORT', '465'),
        'username' => $envOrDefault('MAIL_USERNAME', 'otp@effebit.it'),
        'password' => $envOrDefault('MAIL_PASSWORD', '2S>c(1i82#d}'),
        'encryption' => $envOrDefault('MAIL_ENCRYPTION', 'ssl'),
        'smtp_auth' => $envOrDefault('MAIL_SMTP_AUTH', '1'),
    ],
];