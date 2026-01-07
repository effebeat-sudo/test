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
if (!$cardId) {
    http_response_code(400);
    echo 'ID non valido';
    exit;
}

// --- MODIFICA QUERY: Recupero anche cat.color ---
$stmt = $pdo->prepare('
    SELECT c.*, 
           o.created_by AS owner_creator, 
           lm.email AS last_modifier_email,
           cat.name AS category_name,
           cat.color AS category_color
    FROM cards c 
    JOIN users o ON o.id = c.owner_id 
    LEFT JOIN users lm ON lm.id = c.last_modified_by 
    LEFT JOIN categories cat ON cat.id = c.category_id
    WHERE c.id = ? AND c.deleted_at IS NULL
');
$stmt->execute([$cardId]);
$card = $stmt->fetch();

if (!$card) {
    http_response_code(404);
    echo 'Scheda non trovata';
    exit;
}

// --- CONTROLLO PERMESSI ---
$allowed = false;
if ($currentRole === 'superuser') {
    $allowed = (int)$card['owner_id'] === $currentUserId;
} elseif ($currentRole === 'admin') {
    $allowed = (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId || (int)$card['admin_id'] === $currentUserId;
} else {
    $sameAdmin = $userAdminId && (int)$card['admin_id'] === (int)$userAdminId;
    $allowed = (int)$card['owner_id'] === $currentUserId || ($sameAdmin && $card['privacy_level'] !== 'private');
}
if (!$allowed) {
    http_response_code(403);
    echo 'Accesso non consentito';
    exit;
}

$message = null;
$messageClass = 'success';

$canEdit = false;
if ($currentRole === 'superuser') {
    $canEdit = (int)$card['owner_id'] === $currentUserId;
} elseif ($currentRole === 'admin') {
    $canEdit = (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId || (int)$card['admin_id'] === $currentUserId;
} else {
    $sameAdmin = $userAdminId && (int)$card['admin_id'] === (int)$userAdminId;
    $canEdit = (int)$card['owner_id'] === $currentUserId || ($sameAdmin && $card['privacy_level'] === 'public_rw');
}

$canRestore = $currentRole === 'superuser'
    ? (int)$card['owner_id'] === $currentUserId
    : ($currentRole === 'admin' && $canEdit);

// --- GESTIONE RIPRISTINO BACKUP ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['restore_backup_id'])) {
    if (!$canRestore) {
        $message = 'Non sei autorizzato a ripristinare questa scheda.';
        $messageClass = 'danger';
    } else {
        $backupId = (int)$_POST['restore_backup_id'];
        if (restoreCardBackup($pdo, $cardId, $backupId, $currentUserId)) {
            header('Location: card_view.php?id=' . $cardId . '&restored=1');
            exit;
        }
        $message = 'Ripristino non riuscito.';
        $messageClass = 'danger';
    }
}

if (isset($_GET['restored'])) {
    $message = 'Backup ripristinato con successo.';
    $messageClass = 'success';
    // Ricarica la scheda dopo il ripristino (inclusi i dati categoria)
    $stmt->execute([$cardId]);
    $card = $stmt->fetch();
}

// --- CARICAMENTO VOCI ---
$stmt = $pdo->prepare('SELECT * FROM card_entries WHERE card_id = ?');
$stmt->execute([$cardId]);
$entries = $stmt->fetchAll();
$backups = $canRestore ? getCardBackups($pdo, $cardId) : [];

// Dati per PDF e JS
$cardDataForJs = [
    'name' => $card['name'],
    'category' => $card['category_name'] ?? '',
    'notes' => $card['notes'],
    'entries' => [],
];
foreach ($entries as $entry) {
    $cardDataForJs['entries'][] = [
        'login' => $entry['login'],
        'password' => decryptValue($entry['password_encrypted']),
        'url' => $entry['url'],
        'note' => $entry['note'],
    ];
}
$jsonCardData = json_encode($cardDataForJs, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <link href="assets/style.css" rel="stylesheet">
    <title><?= htmlspecialchars($card['name']) ?></title>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <div class="mb-3">
        <h1 class="h4 mb-2">
            <?= htmlspecialchars($card['name']) ?>
            
            <?php if (!empty($card['category_name'])): ?>
                <?php $catColor = $card['category_color'] ?? '#6c757d'; ?>
                <span class="badge align-middle ms-2 fs-6 fw-normal" 
                      style="background-color: <?= htmlspecialchars($catColor) ?>; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.5);">
                    <i class="bi bi-folder2-open"></i> <?= htmlspecialchars($card['category_name']) ?>
                </span>
            <?php endif; ?>
        </h1>
        
        <div class="d-flex justify-content-between align-items-start">
            <div>
                <div class="mb-1">
                    <?php if ($card['privacy_level'] === 'private'): ?>
                        <span class="badge bg-secondary align-middle">Privata (solo admin)</span>
                    <?php elseif ($card['privacy_level'] === 'public_r'): ?>
                        <span class="badge bg-info align-middle">Pubblica R</span>
                    <?php else: ?>
                        <span class="badge bg-success-subtle text-success align-middle">Pubblica RW</span>
                    <?php endif; ?>
                </div>
                <div class="text-muted small">
                    Ultima modifica: <?= htmlspecialchars(date('Y-m-d H:i', strtotime($card['updated_at']))) ?>
                    <?php if (!empty($card['last_modifier_email'])): ?>
                        da <?= htmlspecialchars($card['last_modifier_email']) ?>
                    <?php endif; ?>
                </div>
            </div>
            <div class="text-end" data-html2canvas-ignore="true">
                <button type="button" class="btn btn-outline-danger btn-sm" onclick="downloadPdf()">
                    <i class="bi bi-file-pdf"></i> Scarica PDF
                </button>
                <?php if ($canEdit): ?>
                    <a href="card_form.php?id=<?= $card['id'] ?>" class="btn btn-outline-secondary btn-sm">Modifica</a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= htmlspecialchars($messageClass) ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div id="content-to-pdf">
        <?php foreach ($entries as $entry): ?>
            <div class="entry-group mb-3">
                <div class="mb-2 d-flex align-items-center pdf-row">
                    <strong class="me-2" style="min-width: 80px;">Login:</strong>
                    <div class="input-group w-50">
                        <input type="text" class="form-control pdf-field" value="<?= htmlspecialchars($entry['login']) ?>" readonly>
                        <button class="btn btn-outline-secondary" type="button" onclick="copySiblingValue(this)" aria-label="Copia login" title="Copia in memoria" data-html2canvas-ignore="true">
                            <i class="bi bi-clipboard"></i>
                        </button>
                    </div>
                </div>
                <div class="mb-2 d-flex align-items-center pdf-row">
                    <strong class="me-2" style="min-width: 80px;">Password:</strong>
                    <div class="input-group w-auto">
                        <input type="password" class="form-control password-field pdf-field" value="<?= htmlspecialchars(decryptValue($entry['password_encrypted'])) ?>" readonly>
                        
                        <button class="btn btn-outline-secondary" type="button" onclick="copySiblingValue(this)" aria-label="Copia password" title="Copia in memoria" data-html2canvas-ignore="true">
                            <i class="bi bi-clipboard"></i>
                        </button>
                        <button class="btn btn-outline-secondary" type="button" onclick="togglePasswordButton(this)" aria-label="Mostra/Nascondi password" title="Visualizza" data-html2canvas-ignore="true">
                            <i class="bi bi-eye"></i>
                        </button>
                    </div>
                </div>
                <div class="d-flex align-items-center pdf-row">
                    <strong class="me-2" style="min-width: 80px;">URL:</strong>
                    <div class="input-group w-75">
                        <input type="url" class="form-control pdf-field" value="<?= htmlspecialchars($entry['url']) ?>" readonly>
                        <button class="btn btn-outline-secondary" type="button" onclick="copySiblingValue(this)" aria-label="Copia URL" title="Copia in memoria" data-html2canvas-ignore="true">
                            <i class="bi bi-clipboard"></i>
                        </button>
                        <button class="btn btn-outline-secondary" type="button" onclick="openUrl(this)" aria-label="Apri URL" title="Apri link" data-html2canvas-ignore="true">
                            <i class="bi bi-box-arrow-up-right"></i>
                        </button>
                    </div>
                </div>
                <div class="mt-2 d-flex align-items-start pdf-row">
                    <strong class="me-2" style="min-width: 80px;">Note blocco:</strong>
                    <div class="input-group w-75">
                        <textarea class="form-control pdf-field" rows="2" readonly><?= htmlspecialchars($entry['note']) ?></textarea>
                        <button class="btn btn-outline-secondary" type="button" onclick="copySiblingValue(this)" aria-label="Copia nota blocco" title="Copia in memoria" data-html2canvas-ignore="true">
                            <i class="bi bi-clipboard"></i>
                        </button>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>

        <div class="card" id="general-notes-card">
            <div class="card-body">
                <h2 class="h6">Note generali</h2>
                <div class="input-group">
                    <textarea class="form-control pdf-field-note" id="general-notes-text" rows="10" readonly><?= htmlspecialchars($card['notes']) ?></textarea>
                    <button class="btn btn-outline-secondary" type="button" onclick="copySiblingValue(this)" aria-label="Copia note scheda" title="Copia in memoria" data-html2canvas-ignore="true">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
            </div>
        </div>
    </div>
    <?php if ($canRestore): ?>
        <div class="card mt-3 mb-3" data-html2canvas-ignore="true">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h2 class="h6 mb-0">Backup disponibili (max 10)</h2>
                </div>
                <?php if (empty($backups)): ?>
                    <p class="text-muted mb-0">Nessun backup registrato.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table align-middle mb-0">
                            <thead>
                                <tr>
                                    <th>Data backup</th>
                                    <th>Creato da</th>
                                    <th class="text-end">Azioni</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($backups as $backup): ?>
                                    <tr>
                                        <td class="small text-muted"><?= htmlspecialchars(date('Y-m-d H:i', strtotime($backup['created_at']))) ?></td>
                                        <td><?= htmlspecialchars($backup['created_by_email'] ?? 'N/A') ?></td>
                                        <td class="text-end">
                                            <form method="post" class="d-inline" onsubmit="return confirm('Ripristinare questo backup? Verranno sovrascritte le modifiche successive.');">
                                                <input type="hidden" name="restore_backup_id" value="<?= (int)$backup['id'] ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-primary">Ripristina</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Dati della scheda iniettati dal PHP
const cardData = <?= $jsonCardData ?>;

function togglePassword(el) {
    const input = el.closest('.input-group')?.querySelector('input[type="password"], input[type="text"]');
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}

function togglePasswordButton(button) {
    const input = button.closest('.input-group')?.querySelector('input[type="password"], input[type="text"]');
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}

function copySiblingValue(button) {
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

function openUrl(button) {
    const inputGroup = button.closest('.input-group');
    const urlField = inputGroup ? inputGroup.querySelector('input[type="url"]') : null;

    const url = (urlField?.value || '').trim();
    if (!url) return;
    
    const urlLower = url.toLowerCase();
    if (urlLower.startsWith('file:')) {
        alert("ATTENZIONE: I percorsi file locali (file:///) vengono bloccati dal browser per sicurezza. Utilizza il pulsante 'Copia URL' (📋).");
        return; 
    }

    const hasScheme = /^[a-zA-Z]+:\/\//.test(url);
    let prefixedUrl = url;

    if (!hasScheme) {
        prefixedUrl = 'http://' + url;
    }

    window.open(prefixedUrl, '_blank');
}

function buildTextualPdfContent() {
    let html = `
        <style>
            body { font-family: sans-serif; line-height: 1.6; padding: 20px; }
            h2 { color: #1e88e5; border-bottom: 2px solid #ddd; padding-bottom: 5px; margin-top: 20px; }
            .entry { margin-bottom: 20px; padding: 15px; border: 1px solid #eee; border-radius: 8px; }
            .field-label { font-weight: bold; color: #333; display: inline-block; min-width: 100px; }
            .field-value { display: inline; word-wrap: break-word; white-space: pre-wrap; }
            .entry-divider { margin-top: 10px; border-top: 1px dashed #ccc; }
            .section-header { color: #1565c0; font-size: 1.1em; font-weight: bold; margin-bottom: 10px; padding-bottom: 5px; border-bottom: 1px solid #e0e0e0; }
        </style>
        
        <h1>Scheda: ${cardData.name}</h1>
    `;
    
    if (cardData.category) {
        html += `<p><strong>Categoria:</strong> ${cardData.category}</p>`;
    }

    if (cardData.entries && cardData.entries.length > 0) {
        cardData.entries.forEach((entry, index) => {
            let entryContent = '';
            let hasContent = false;

            if (entry.login && entry.login.trim() !== '') {
                entryContent += `<p><span class="field-label">Login:</span> <span class="field-value">${entry.login}</span></p>`;
                hasContent = true;
            }
            if (entry.password && entry.password.trim() !== '') {
                entryContent += `<p><span class="field-label">Password:</span> <span class="field-value">${entry.password}</span></p>`;
                hasContent = true;
            }
            if (entry.url && entry.url.trim() !== '') {
                entryContent += `<p><span class="field-label">URL:</span> <span class="field-value">${entry.url}</span></p>`;
                hasContent = true;
            }
            if (entry.note && entry.note.trim() !== '') {
                entryContent += `<p><span class="field-label">Note Blocco:</span><br><span class="field-value">${entry.note}</span></p>`;
                hasContent = true;
            }

            if (hasContent) {
                 html += `<div class="entry">
                             <div class="section-header">Blocco Credenziali ${index + 1}</div>
                             ${entryContent}
                         </div>`;
            }
        });
    }

    if (cardData.notes && cardData.notes.trim() !== '') {
        html += `
            <h2>Note Generali</h2>
            <div class="field-value">${cardData.notes.trim()}</div>
        `;
    }

    return html;
}

function downloadPdf() {
    const cardName = cardData.name;
    const pdfContentHtml = buildTextualPdfContent(); 

    const opt = {
        margin:       10,
        filename:     cardName + '.pdf',
        image:        { type: 'jpeg', quality: 0.98 },
        html2canvas:  { scale: 2 }, 
        jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
    };

    html2pdf().set(opt).from(pdfContentHtml, 'string').save();
}
</script>
</body>
</html>