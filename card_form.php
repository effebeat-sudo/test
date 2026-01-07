<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/backup.php';
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
$categoryId = null;
$entries = [['login' => '', 'password' => '', 'url' => '', 'note' => '']];
$privacyLevel = 'public_rw';

// --- 1. RECUPERO CATEGORIE DISPONIBILI ---
$adminIdForCats = ($currentRole === 'user') ? ($userAdminId ?? 0) : $currentUserId;
$stmtCats = $pdo->prepare("SELECT id, name FROM categories WHERE created_by_admin = ? ORDER BY name ASC");
$stmtCats->execute([$adminIdForCats]);
$availableCategories = $stmtCats->fetchAll(PDO::FETCH_ASSOC);

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
    $categoryId = $card['category_id'];

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
    
    // Gestione Categoria (Esistente o Nuova)
    $categoryIdInput = isset($_POST['category_id']) ? (int)$_POST['category_id'] : null;
    $newCategoryName = trim($_POST['new_category_name'] ?? '');

    // Se è stata selezionata l'opzione "Crea Nuova" (-1) e c'è un nome
    if ($categoryIdInput === -1 && !empty($newCategoryName)) {
        if ($currentRole === 'user') {
             // Opzionale: impedire agli utenti semplici di creare categorie se non vuoi
             // $errors[] = "Non hai i permessi per creare categorie.";
        }
        
        // Verifica duplicati prima di inserire
        $stmtCheck = $pdo->prepare("SELECT id FROM categories WHERE name = ? AND created_by_admin = ?");
        $stmtCheck->execute([$newCategoryName, $adminIdForCats]);
        $existingCat = $stmtCheck->fetch();

        if ($existingCat) {
            $categoryIdInput = $existingCat['id']; // Usa quella esistente se c'è già
        } else {
            // Crea nuova categoria
            $stmtNewCat = $pdo->prepare("INSERT INTO categories (name, created_by_admin) VALUES (?, ?)");
            if ($stmtNewCat->execute([$newCategoryName, $adminIdForCats])) {
                $categoryIdInput = $pdo->lastInsertId();
            } else {
                $errors[] = "Errore durante la creazione della categoria.";
            }
        }
    } elseif ($categoryIdInput <= 0) {
        $categoryIdInput = null; // Nessuna categoria selezionata
    }

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
        $noteVal = trim($entryNotes[$i] ?? '');
        $entries[] = ['login' => $loginVal, 'password' => $passVal, 'url' => $urlVal, 'note' => $noteVal];
    }

    if (empty($entries)) {
        $entries[] = ['login' => '', 'password' => '', 'url' => '', 'note' => ''];
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
            if (!createCardBackup($pdo, $cardId, $currentUserId)) {
                $errors[] = 'Impossibile creare il backup della scheda.';
            }
        }

        if (empty($errors) && $editing) {
            $stmt = $pdo->prepare('UPDATE cards SET name = ?, notes = ?, privacy_level = ?, category_id = ?, updated_at = NOW(), last_modified_by = ? WHERE id = ?');
            $stmt->execute([$name, $notes, $privacyLevel, $categoryIdInput, $currentUserId, $cardId]);
            $pdo->prepare('DELETE FROM card_entries WHERE card_id = ?')->execute([$cardId]);
        } elseif (empty($errors)) {
            $adminId = null;
            if ($currentRole === 'admin') {
                $adminId = $currentUserId;
            } elseif ($currentRole === 'user') {
                $adminId = $currentUser['created_by'] ?? null;
            }

            $stmt = $pdo->prepare('INSERT INTO cards (name, notes, owner_id, admin_id, privacy_level, category_id, created_at, updated_at, last_modified_by) VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW(), ?)');
            $stmt->execute([$name, $notes, $currentUserId, $adminId, $privacyLevel, $categoryIdInput, $currentUserId]);
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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title><?= $editing ? 'Modifica scheda' : 'Nuova scheda' ?></title>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0"><?= $editing ? 'Modifica scheda' : 'Nuova scheda' ?></h1>
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

    <form method="post" id="card-form" autocomplete="off">
        <div class="d-flex justify-content-end mb-3">
            <button type="submit" class="btn btn-success">Salva scheda</button>
        </div>
        
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label class="form-label" for="name">Nome scheda</label>
                        <input type="text" class="form-control" id="name" name="name" value="<?= htmlspecialchars($name) ?>" maxlength="255" required autocomplete="off">
                    </div>
                    
                    <div class="col-md-6 mb-3">
                        <label class="form-label" for="category_id">Categoria</label>
                        <select class="form-select" id="category_id" name="category_id">
                            <option value="0">-- Nessuna Categoria --</option>
                            <?php foreach ($availableCategories as $cat): ?>
                                <option value="<?= $cat['id'] ?>" <?= ($categoryId == $cat['id']) ? 'selected' : '' ?>>
                                    <?= htmlspecialchars($cat['name']) ?>
                                </option>
                            <?php endforeach; ?>
                            
                            <option value="-1" class="fw-bold text-primary">+ Crea nuova categoria...</option>
                        </select>
                        
                        <div id="new_category_input_group" class="mt-2 d-none">
                            <input type="text" class="form-control" id="new_category_name" name="new_category_name" placeholder="Inserisci nome nuova categoria">
                        </div>
                    </div>
                </div>

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

                <div class="mb-0">
                    <label for="notes" class="form-label">Note</label>
                    <textarea class="form-control" name="notes" id="notes" rows="4"><?= htmlspecialchars($notes) ?></textarea>
                </div>
            </div>
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
                        <input type="text" class="form-control" name="entry_login[]" value="<?= htmlspecialchars($entry['login']) ?>" autocomplete="off">
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia login" title="Copia in memoria">
                            <i class="bi bi-clipboard"></i>
                            <span class="visually-hidden">Copia in memoria</span>
                        </button>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label">Password</label>
                    <div class="input-group">
                        <input type="password" class="form-control" name="entry_password[]" value="<?= htmlspecialchars($entry['password']) ?>" autocomplete="new-password">
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia password" title="Copia in memoria">
                            <i class="bi bi-clipboard"></i>
                            <span class="visually-hidden">Copia in memoria</span>
                        </button>
                        <button class="btn btn-outline-secondary" type="button" onclick="togglePassword(this)" aria-label="Mostra/Nascondi password" title="Visualizza">
                            <i class="bi bi-eye"></i>
                            <span class="visually-hidden">Visualizza</span>
                        </button>
                    </div>
                </div>
                <div class="mb-0">
                    <label class="form-label">URL</label>
                    <div class="input-group">
                        <input type="url" class="form-control" name="entry_url[]" value="<?= htmlspecialchars($entry['url']) ?>" autocomplete="off">
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia URL" title="Copia in memoria">
                            <i class="bi bi-clipboard"></i>
                            <span class="visually-hidden">Copia in memoria</span>
                        </button>
                        <button class="btn btn-outline-secondary" type="button" onclick="openUrl(this)" aria-label="Apri URL" title="Apri link">
                            <i class="bi bi-box-arrow-up-right"></i>
                            <span class="visually-hidden">Apri link</span>
                        </button>
                    </div>
                </div>
                <div class="mb-0 mt-3">
                    <label class="form-label">Note blocco</label>
                    <div class="input-group">
                        <textarea class="form-control" name="entry_note[]" rows="2" autocomplete="off"><?= htmlspecialchars($entry['note'] ?? '') ?></textarea>
                        <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia nota blocco" title="Copia in memoria">
                            <i class="bi bi-clipboard"></i>
                            <span class="visually-hidden">Copia in memoria</span>
                        </button>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <button type="button" class="btn btn-outline-primary mb-3" id="add-entry">+ Aggiungi blocco</button>

        <button type="submit" class="btn btn-success">Salva scheda</button>
    </form>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Gestione visualizzazione campo "Nuova Categoria"
document.getElementById('category_id').addEventListener('change', function() {
    const newCatGroup = document.getElementById('new_category_input_group');
    const newCatInput = document.getElementById('new_category_name');
    
    if (this.value === '-1') {
        newCatGroup.classList.remove('d-none');
        newCatInput.focus();
        newCatInput.required = true;
    } else {
        newCatGroup.classList.add('d-none');
        newCatInput.value = '';
        newCatInput.required = false;
    }
});

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
                <input type="text" class="form-control" name="entry_login[]" autocomplete="off">
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia login" title="Copia in memoria">
                    <i class="bi bi-clipboard"></i>
                    <span class="visually-hidden">Copia in memoria</span>
                </button>
            </div>
        </div>
        <div class="mb-3">
            <label class="form-label">Password</label>
            <div class="input-group">
                <input type="password" class="form-control" name="entry_password[]" autocomplete="new-password">
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia password" title="Copia in memoria">
                    <i class="bi bi-clipboard"></i>
                    <span class="visually-hidden">Copia in memoria</span>
                </button>
                <button class="btn btn-outline-secondary" type="button" onclick="togglePassword(this)" aria-label="Mostra/Nascondi password" title="Visualizza">
                    <i class="bi bi-eye"></i>
                    <span class="visually-hidden">Visualizza</span>
                </button>
            </div>
        </div>
        <div class="mb-0">
            <label class="form-label">URL</label>
            <div class="input-group">
                <input type="url" class="form-control" name="entry_url[]" autocomplete="off">
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia URL" title="Copia in memoria">
                    <i class="bi bi-clipboard"></i>
                    <span class="visually-hidden">Copia in memoria</span>
                </button>
                <button class="btn btn-outline-secondary" type="button" onclick="openUrl(this)" aria-label="Apri URL" title="Apri link">
                    <i class="bi bi-box-arrow-up-right"></i>
                    <span class="visually-hidden">Apri link</span>
                </button>
            </div>
        </div>
        <div class="mb-0 mt-3">
            <label class="form-label">Note blocco</label>
            <div class="input-group">
                <textarea class="form-control" name="entry_note[]" rows="2" autocomplete="off"></textarea>
                <button class="btn btn-outline-secondary" type="button" onclick="copyValue(this)" aria-label="Copia nota blocco" title="Copia in memoria">
                    <i class="bi bi-clipboard"></i>
                    <span class="visually-hidden">Copia in memoria</span>
                </button>
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

function togglePassword(button) {
    const input = button.closest('.input-group')?.querySelector('input[type="password"], input[type="text"]');
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}

function openUrl(el) {
    const input = el.closest('.input-group')?.querySelector('input[type="url"]');
    const url = (input?.value || '').trim();
    if (!url) return;
    window.open(url, '_blank');
}

function copyValue(button) {
    const field = button.previousElementSibling;
    const value = field?.value ?? field?.textContent ?? '';
    if (!navigator.clipboard) {
        alert('Copia non supportata dal browser');
        return;
    }
    if (!button.dataset.originalHtml) {
        button.dataset.originalHtml = button.innerHTML;
    }
    navigator.clipboard.writeText(value).then(() => {
        button.innerHTML = '<i class="bi bi-check"></i>';
        setTimeout(() => (button.innerHTML = button.dataset.originalHtml), 1000);
    }).catch(() => {
        alert('Impossibile copiare negli appunti');
    });
}

updateRemoveButtons();
</script>
</body>
</html>