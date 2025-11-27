<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
requireLogin();

$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';

$cardId = isset($_GET['id']) ? (int)$_GET['id'] : null;
if (!$cardId) {
    http_response_code(400);
    echo 'ID non valido';
    exit;
}

$stmt = $pdo->prepare('SELECT * FROM cards WHERE id = ?');
$stmt->execute([$cardId]);
$card = $stmt->fetch();
if (!$card) {
    http_response_code(404);
    echo 'Scheda non trovata';
    exit;
}

$allowed = $currentRole === 'superuser'
    || ($card['admin_id'] && (int)$card['admin_id'] === $currentUserId)
    || (int)$card['owner_id'] === $currentUserId;
if (!$allowed) {
    http_response_code(403);
    echo 'Accesso non consentito';
    exit;
}

$stmt = $pdo->prepare('SELECT * FROM card_entries WHERE card_id = ?');
$stmt->execute([$cardId]);
$entries = $stmt->fetchAll();
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title><?= htmlspecialchars($card['name']) ?></title>
</head>
<body>
<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0"><?= htmlspecialchars($card['name']) ?></h1>
        <div>
            <a href="cards.php" class="btn btn-link">Torna alla lista</a>
            <a href="card_form.php?id=<?= $card['id'] ?>" class="btn btn-outline-secondary btn-sm">Modifica</a>
            <a href="logout.php" class="btn btn-link">Logout</a>
        </div>
    </div>

    <?php foreach ($entries as $entry): ?>
        <div class="entry-group mb-3">
            <div class="mb-2"><strong>Login:</strong> <?= htmlspecialchars($entry['login']) ?></div>
            <div class="mb-2">
                <strong>Password:</strong>
                <input type="password" class="form-control d-inline-block w-auto" value="<?= htmlspecialchars(decryptValue($entry['password_encrypted'])) ?>" readonly>
                <span class="password-toggle" onclick="togglePassword(this)">👁</span>
            </div>
            <div>
                <strong>URL:</strong>
                <input type="url" class="form-control d-inline-block w-50" value="<?= htmlspecialchars($entry['url']) ?>" readonly>
                <span class="url-open" onclick="window.open('<?= htmlspecialchars($entry['url']) ?>', '_blank')">🔗</span>
            </div>
        </div>
    <?php endforeach; ?>

    <div class="card">
        <div class="card-body">
            <h2 class="h6">Note</h2>
            <p class="mb-0"><?= nl2br(htmlspecialchars($card['notes'])) ?></p>
        </div>
    </div>
</div>
<script>
function togglePassword(el) {
    const input = el.previousElementSibling;
    if (input.type === 'password') {
        input.type = 'text';
    } else {
        input.type = 'password';
    }
}
</script>
</body>
</html>
