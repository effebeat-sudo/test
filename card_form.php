<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
requireLogin();

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';

$cardId = isset($_GET['id']) ? (int)$_GET['id'] : null;
$editing = $cardId !== null;
$errors = [];
$name = '';
$notes = '';
$entries = [['login' => '', 'password' => '', 'url' => '']];

if ($editing) {
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
    $name = $card['name'];
    $notes = $card['notes'];

    $stmt = $pdo->prepare('SELECT * FROM card_entries WHERE card_id = ?');
    $stmt->execute([$cardId]);
    $entries = [];
    foreach ($stmt->fetchAll() as $entry) {
        $entries[] = [
            'login' => $entry['login'],
            'password' => decryptValue($entry['password_encrypted']),
            'url' => $entry['url'],
        ];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $notes = trim($_POST['notes'] ?? '');
    $logins = $_POST['entry_login'] ?? [];
    $passwords = $_POST['entry_password'] ?? [];
    $urls = $_POST['entry_url'] ?? [];

    if ($name === '') {
        $errors[] = 'Il nome della scheda è obbligatorio.';
    }

    $entries = [];
    for ($i = 0; $i < count($logins); $i++) {
        $loginVal = trim($logins[$i]);
        $passVal = $passwords[$i];
        $urlVal = trim($urls[$i]);
        if ($loginVal === '' && $passVal === '' && $urlVal === '') {
            continue;
        }
        $entries[] = ['login' => $loginVal, 'password' => $passVal, 'url' => $urlVal];
    }

    if (empty($entries)) {
        $errors[] = 'Inserisci almeno un blocco login/password/url.';
    }

    if (empty($errors)) {
        if ($editing) {
            $stmt = $pdo->prepare('UPDATE cards SET name = ?, notes = ? WHERE id = ?');
            $stmt->execute([$name, $notes, $cardId]);
            $pdo->prepare('DELETE FROM card_entries WHERE card_id = ?')->execute([$cardId]);
        } else {
            $adminId = null;
            if ($currentRole === 'admin') {
                $adminId = $currentUserId;
            } elseif ($currentRole === 'user') {
                $adminId = $currentUser['created_by'] ?? null;
            }

            $stmt = $pdo->prepare('INSERT INTO cards (name, notes, owner_id, admin_id, created_at) VALUES (?, ?, ?, ?, NOW())');
            $stmt->execute([$name, $notes, $currentUserId, $adminId]);
            $cardId = (int)$pdo->lastInsertId();
        }

        $stmt = $pdo->prepare('INSERT INTO card_entries (card_id, login, password_encrypted, url) VALUES (?, ?, ?, ?)');
        foreach ($entries as $entry) {
            $stmt->execute([
                $cardId,
                $entry['login'],
                encryptValue($entry['password']),
                $entry['url'],
            ]);
        }

        header('Location: card_view.php?id=' . $cardId);
        exit;
    }
}
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title><?= $editing ? 'Modifica scheda' : 'Nuova scheda' ?></title>
</head>
<body>
<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0"><?= $editing ? 'Modifica scheda' : 'Nuova scheda' ?></h1>
        <div>
            <a href="cards.php" class="btn btn-link">Torna alla lista</a>
            <a href="logout.php" class="btn btn-link">Logout</a>
        </div>
    </div>

    <?php if ($errors): ?>
        <div class="alert alert-danger">
            <ul class="mb-0">
                <?php foreach ($errors as $error): ?>
                    <li><?= htmlspecialchars($error) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="post" id="card-form">
        <div class="mb-3">
            <label class="form-label" for="name">Nome scheda</label>
            <input type="text" class="form-control" id="name" name="name" value="<?= htmlspecialchars($name) ?>" required>
        </div>

        <div id="entries">
            <?php foreach ($entries as $index => $entry): ?>
                <div class="entry-group mb-3" data-entry>
                    <div class="d-flex justify-content-between mb-2">
                        <strong>Blocco credenziali</strong>
                        <button type="button" class="btn btn-sm btn-outline-danger remove-entry" <?= count($entries) === 1 ? 'style="display:none"' : '' ?>>-</button>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Login</label>
                        <input type="text" class="form-control" name="entry_login[]" value="<?= htmlspecialchars($entry['login']) ?>">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password <span class="password-toggle" onclick="togglePassword(this)">👁</span></label>
                        <input type="password" class="form-control" name="entry_password[]" value="<?= htmlspecialchars($entry['password']) ?>">
                    </div>
                    <div class="mb-0">
                        <label class="form-label">URL <span class="url-open" onclick="openUrl(this)">🔗</span></label>
                        <input type="url" class="form-control" name="entry_url[]" value="<?= htmlspecialchars($entry['url']) ?>">
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        <button type="button" class="btn btn-outline-primary mb-3" id="add-entry">+ Aggiungi blocco</button>

        <div class="mb-3">
            <label for="notes" class="form-label">Note</label>
            <textarea class="form-control" name="notes" id="notes" rows="4"><?= htmlspecialchars($notes) ?></textarea>
        </div>

        <button type="submit" class="btn btn-success">Salva scheda</button>
    </form>
</div>
<script>
const template = () => {
    return `
    <div class="entry-group mb-3" data-entry>
        <div class="d-flex justify-content-between mb-2">
            <strong>Blocco credenziali</strong>
            <button type="button" class="btn btn-sm btn-outline-danger remove-entry">-</button>
        </div>
        <div class="mb-3">
            <label class="form-label">Login</label>
            <input type="text" class="form-control" name="entry_login[]">
        </div>
        <div class="mb-3">
            <label class="form-label">Password <span class="password-toggle" onclick="togglePassword(this)">👁</span></label>
            <input type="password" class="form-control" name="entry_password[]">
        </div>
        <div class="mb-0">
            <label class="form-label">URL <span class="url-open" onclick="openUrl(this)">🔗</span></label>
            <input type="url" class="form-control" name="entry_url[]">
        </div>
    </div>`;
};

document.getElementById('add-entry').addEventListener('click', () => {
    const container = document.getElementById('entries');
    container.insertAdjacentHTML('beforeend', template());
    updateRemoveButtons();
});

function updateRemoveButtons() {
    const groups = document.querySelectorAll('[data-entry]');
    groups.forEach(btn => {
        const removeBtn = btn.querySelector('.remove-entry');
        if (removeBtn) {
            removeBtn.style.display = groups.length > 1 ? 'inline-block' : 'none';
            removeBtn.onclick = () => {
                btn.remove();
                updateRemoveButtons();
            };
        }
    });
}

function togglePassword(el) {
    const input = el.parentElement.nextElementSibling;
    if (input.type === 'password') {
        input.type = 'text';
    } else {
        input.type = 'password';
    }
}

function openUrl(el) {
    const input = el.parentElement.nextElementSibling;
    if (input.value) {
        window.open(input.value, '_blank');
    }
}

updateRemoveButtons();
</script>
</body>
</html>
