<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
requireLogin();

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';
$userAdminId = $currentUser['created_by'] ?? null;

$cardId = isset($_GET['id']) ? (int)$_GET['id'] : null;
$editing = $cardId !== null;
$errors = [];
$name = '';
$notes = '';
$entries = [['login' => '', 'password' => '', 'url' => '', 'note' => '']];
$privacyLevel = 'public_rw';

if ($editing) {
    $stmt = $pdo->prepare('SELECT c.*, o.created_by AS owner_creator FROM cards c JOIN users o ON o.id = c.owner_id WHERE c.id = ? AND c.deleted_at IS NULL');
    $stmt->execute([$cardId]);
    $card = $stmt->fetch();
    if (!$card) {
        http_response_code(404);
        echo 'Scheda non trovata';
        exit;
    }
    $allowed = false;
    if ($currentRole === 'superuser') {
        $allowed = (int)$card['owner_id'] === $currentUserId;
    } elseif ($currentRole === 'admin') {
        $allowed = (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId || (int)$card['admin_id'] === $currentUserId;
    } else {
        $sameAdmin = $userAdminId && (int)$card['admin_id'] === (int)$userAdminId;
        $allowed = (int)$card['owner_id'] === $currentUserId || ($sameAdmin && $card['privacy_level'] === 'public_rw');
    }
    if (!$allowed) {
        http_response_code(403);
        echo 'Accesso non consentito';
        exit;
    }
    $name = $card['name'];
    $notes = $card['notes'];
    $privacyLevel = $card['privacy_level'];

    $stmt = $pdo->prepare('SELECT * FROM card_entries WHERE card_id = ?');
    $stmt->execute([$cardId]);
    $entries = [];
    foreach ($stmt->fetchAll() as $entry) {
        $entries[] = [
            'login' => $entry['login'],
            'password' => decryptValue($entry['password_encrypted']),
            'url' => $entry['url'],
            'note' => $entry['note'] ?? '',
        ];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $notes = trim($_POST['notes'] ?? '');
    $logins = $_POST['entry_login'] ?? [];
    $passwords = $_POST['entry_password'] ?? [];
    $urls = $_POST['entry_url'] ?? [];
    $entryNotes = $_POST['entry_note'] ?? [];
    $canTogglePrivacy = $currentRole === 'admin';

    if ($editing && isset($card)) {
        $canTogglePrivacy = $canTogglePrivacy && ((int)$card['admin_id'] === $currentUserId || (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId);
    }

    if ($name === '') {
        $errors[] = 'Il nome della scheda è obbligatorio.';
    } elseif (mb_strlen($name) > 255) {
        $errors[] = 'Il nome della scheda non può superare 255 caratteri.';
    }

    $entries = [];
    for ($i = 0; $i < count($logins); $i++) {
        $loginVal = trim($logins[$i]);
        $passVal = $passwords[$i];
        $urlVal = trim($urls[$i]);
        if ($loginVal === '' && $passVal === '' && $urlVal === '') {
            continue;
        }
        $noteVal = trim($entryNotes[$i] ?? '');
        $entries[] = ['login' => $loginVal, 'password' => $passVal, 'url' => $urlVal, 'note' => $noteVal];
    }

    if (empty($entries)) {
        $errors[] = 'Inserisci almeno un blocco login/password/url.';
    }

    if ($currentRole === 'superuser') {
        $privacyLevel = 'private';
    } elseif ($canTogglePrivacy) {
        $postedPrivacy = $_POST['privacy_level'] ?? 'public_rw';
        if (in_array($postedPrivacy, ['private', 'public_rw', 'public_r'], true)) {
            $privacyLevel = $postedPrivacy;
        }
    } else {
        $privacyLevel = 'public_rw';
    }

    if (empty($errors)) {
        if ($editing) {
            $stmt = $pdo->prepare('UPDATE cards SET name = ?, notes = ?, privacy_level = ?, updated_at = NOW(), last_modified_by = ? WHERE id = ?');
            $stmt->execute([$name, $notes, $privacyLevel, $currentUserId, $cardId]);
            $pdo->prepare('DELETE FROM card_entries WHERE card_id = ?')->execute([$cardId]);
        } else {
            $adminId = null;
            if ($currentRole === 'admin') {
                $adminId = $currentUserId;
            } elseif ($currentRole === 'user') {
                $adminId = $currentUser['created_by'] ?? null;
            }

            $stmt = $pdo->prepare('INSERT INTO cards (name, notes, owner_id, admin_id, privacy_level, created_at, updated_at, last_modified_by) VALUES (?, ?, ?, ?, ?, NOW(), NOW(), ?)');
            $stmt->execute([$name, $notes, $currentUserId, $adminId, $privacyLevel, $currentUserId]);
            $cardId = (int)$pdo->lastInsertId();
        }

        $stmt = $pdo->prepare('INSERT INTO card_entries (card_id, login, password_encrypted, url, note) VALUES (?, ?, ?, ?, ?)');
        foreach ($entries as $entry) {
            $stmt->execute([
                $cardId,
                $entry['login'],
                encryptValue($entry['password']),
                $entry['url'],
                $entry['note'],
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
            <input type="text" class="form-control" id="name" name="name" value="<?= htmlspecialchars($name) ?>" maxlength="255" required>
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
                    <div class="input-group">
                        <input type="text" class="form-control" name="entry_login[]" value="<?= htmlspecialchars($entry['login']) ?>">
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia login">📋</button>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label">Password <span class="password-toggle" onclick="togglePassword(this)">👁</span></label>
                    <div class="input-group">
                        <input type="password" class="form-control" name="entry_password[]" value="<?= htmlspecialchars($entry['password']) ?>">
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia password">📋</button>
                    </div>
                </div>
                <div class="mb-0">
                    <label class="form-label">URL <span class="url-open" onclick="openUrl(this)">🔗</span></label>
                    <div class="input-group">
                        <input type="url" class="form-control" name="entry_url[]" value="<?= htmlspecialchars($entry['url']) ?>">
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia URL">📋</button>
                    </div>
                </div>
                <div class="mb-0 mt-3">
                    <label class="form-label">Note blocco</label>
                    <div class="input-group">
                        <textarea class="form-control" name="entry_note[]" rows="2"><?= htmlspecialchars($entry['note'] ?? '') ?></textarea>
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia nota blocco">📋</button>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <button type="button" class="btn btn-outline-primary mb-3" id="add-entry">+ Aggiungi blocco</button>

        <?php if ($currentRole === 'admin'): ?>
            <div class="mb-3">
                <label class="form-label" for="privacy_level">Privacy scheda</label>
                <select class="form-select" id="privacy_level" name="privacy_level">
                    <option value="public_rw" <?= $privacyLevel === 'public_rw' ? 'selected' : '' ?>>Pubblica (lettura e scrittura per tutti gli utenti dell'admin)</option>
                    <option value="public_r" <?= $privacyLevel === 'public_r' ? 'selected' : '' ?>>Pubblica R (lettura per tutti gli utenti dell'admin, scrittura solo admin)</option>
                    <option value="private" <?= $privacyLevel === 'private' ? 'selected' : '' ?>>Privata (visibile solo all'admin e proprietario)</option>
                </select>
                <div class="form-text">Il superuser imposta automaticamente le proprie schede come private.</div>
            </div>
        <?php endif; ?>

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
            <div class="input-group">
                <input type="text" class="form-control" name="entry_login[]">
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia login">📋</button>
            </div>
        </div>
        <div class="mb-3">
            <label class="form-label">Password <span class="password-toggle" onclick="togglePassword(this)">👁</span></label>
            <div class="input-group">
                <input type="password" class="form-control" name="entry_password[]">
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia password">📋</button>
            </div>
        </div>
        <div class="mb-0">
            <label class="form-label">URL <span class="url-open" onclick="openUrl(this)">🔗</span></label>
            <div class="input-group">
                <input type="url" class="form-control" name="entry_url[]">
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia URL">📋</button>
            </div>
        </div>
        <div class="mb-0 mt-3">
            <label class="form-label">Note blocco</label>
            <div class="input-group">
                <textarea class="form-control" name="entry_note[]" rows="2"></textarea>
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia nota blocco">📋</button>
            </div>
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
    const input = el.closest('.mb-3')?.querySelector('input[name="entry_password[]"]');
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}

function openUrl(el) {
    const input = el.parentElement.nextElementSibling;
    if (input.value) {
        window.open(input.value, '_blank');
    }
}

function copyValue(button) {
    const field = button.previousElementSibling;
    const value = field?.value ?? '';
    if (!navigator.clipboard) {
        alert('Copia non supportata dal browser');
        return;
    }
    navigator.clipboard.writeText(value).then(() => {
        button.innerText = '✔';
        setTimeout(() => (button.innerText = '📋'), 1000);
    }).catch(() => {
        alert('Impossibile copiare negli appunti');
    });
}

updateRemoveButtons();
</script>
</body>
</html>