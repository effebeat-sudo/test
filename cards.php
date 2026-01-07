<?php
require_once __DIR__ . '/includes/auth.php';
requireLogin();

require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/backup.php';

// Placeholder funzioni se non presenti in auth.php
if (!function_exists('currentUser')) { function currentUser($p){ return null; } }
if (!function_exists('isImpersonating')) { function isImpersonating(){ return false; } }
if (!function_exists('stopImpersonation')) { function stopImpersonation($p){ return false; } }

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';
$userAdminId = $currentUser['created_by'] ?? null;
$impersonating = isImpersonating();
$impersonatorEmail = $_SESSION['impersonator_email'] ?? null;

$message = null;
$messageClass = 'success';

// --- 1. GESTIONE POST (Azioni) ---

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // A. Stop Impersonificazione
    if (isset($_POST['stop_impersonation'])) {
        if (stopImpersonation($pdo)) {
            header('Location: cards.php');
            exit;
        }
        $message = 'Impossibile terminare l\'impersonificazione.';
        $messageClass = 'danger';
    } 
    
    // B. Sposta nel Cestino (Singolo)
    elseif (isset($_POST['delete_id'])) {
        $deleteId = (int)$_POST['delete_id'];
        $stmt = $pdo->prepare('SELECT c.id, c.admin_id, c.owner_id, o.created_by AS owner_creator FROM cards c JOIN users o ON o.id = c.owner_id WHERE c.id = ?');
        $stmt->execute([$deleteId]);
        $card = $stmt->fetch();

        $allowed = false;
        if ($card) {
            if ($currentRole === 'superuser') {
                $allowed = (int)$card['owner_id'] === $currentUserId;
            } elseif ($currentRole === 'admin') {
                $allowed = (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId || (int)$card['admin_id'] === $currentUserId;
            } else {
                $allowed = (int)$card['owner_id'] === $currentUserId;
            }
        }

        if ($allowed) {
            $stmt = $pdo->prepare('UPDATE cards SET deleted_at = NOW(), deleted_by = ? WHERE id = ?');
            $stmt->execute([$currentUserId, $deleteId]);
            $message = "Scheda spostata nel cestino (ID: {$deleteId}).";
        } else {
            $message = "Non hai il permesso di eliminare questa scheda.";
            $messageClass = 'danger';
        }
    }

    // C. ASSEGNAZIONE CATEGORIA (SINGOLA O MASSIVA)
    elseif (isset($_POST['assign_category_action'])) {
        // Recupera ID singolo o lista di ID (massiva)
        $targetCardIds = [];
        
        if (!empty($_POST['bulk_card_ids'])) {
            $rawIds = explode(',', $_POST['bulk_card_ids']);
            $targetCardIds = array_map('intval', $rawIds);
        } elseif (!empty($_POST['card_id'])) {
            $targetCardIds = [(int)$_POST['card_id']];
        }

        $selectedCatId = (int)($_POST['category_id'] ?? 0);
        $newCatName = trim($_POST['new_category_name'] ?? '');
        
        if (empty($targetCardIds)) {
            $message = "Nessuna scheda selezionata.";
            $messageClass = 'warning';
        } else {
            $finalCatId = null;

            // Logica Creazione Nuova Categoria
            if (!empty($newCatName)) {
                $stmtCatCheck = $pdo->prepare("SELECT id FROM categories WHERE name = ? AND created_by_admin = ?");
                $catOwnerId = ($currentRole === 'user') ? $userAdminId : $currentUserId;
                
                $stmtCatCheck->execute([$newCatName, $catOwnerId]);
                $existingCat = $stmtCatCheck->fetch();

                if ($existingCat) {
                    $finalCatId = $existingCat['id'];
                } else {
                    $stmtCat = $pdo->prepare("INSERT INTO categories (name, color, created_by_admin) VALUES (?, '#1e88e5', ?)");
                    if ($stmtCat->execute([$newCatName, $catOwnerId])) {
                        $finalCatId = $pdo->lastInsertId();
                    }
                }
            } elseif ($selectedCatId > 0) {
                $finalCatId = $selectedCatId;
            } else {
                $finalCatId = null; 
            }

            $updatedCount = 0;
            $stmtCheck = $pdo->prepare('SELECT c.id, c.owner_id, c.admin_id, o.created_by AS owner_creator FROM cards c JOIN users o ON o.id = c.owner_id WHERE c.id = ?');
            $stmtUpd = $pdo->prepare("UPDATE cards SET category_id = ?, last_modified_by = ?, updated_at = NOW() WHERE id = ?");

            foreach ($targetCardIds as $cId) {
                if ($cId <= 0) continue;
                
                $stmtCheck->execute([$cId]);
                $card = $stmtCheck->fetch();
                
                $canEdit = false;
                if ($card) {
                    if ($currentRole === 'superuser') {
                        $canEdit = (int)$card['owner_id'] === $currentUserId;
                    } elseif ($currentRole === 'admin') {
                        $canEdit = (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId || (int)$card['admin_id'] === $currentUserId;
                    } else {
                        $canEdit = (int)$card['owner_id'] === $currentUserId;
                    }
                }

                if ($canEdit) {
                    $stmtUpd->execute([$finalCatId, $currentUserId, $cId]);
                    $updatedCount++;
                }
            }

            if ($updatedCount > 0) {
                $message = "Categoria aggiornata per $updatedCount schede.";
            } else {
                $message = "Nessuna scheda aggiornata (permessi insufficienti o selezione vuota).";
                $messageClass = 'warning';
            }
        }
    }
}

// --- 2. PREPARAZIONE DATI ---
$adminIdForCats = ($currentRole === 'user') ? ($userAdminId ?? 0) : $currentUserId;
$stmtCats = $pdo->prepare("SELECT id, name, color FROM categories WHERE created_by_admin = ? ORDER BY name ASC");
$stmtCats->execute([$adminIdForCats]);
$availableCategories = $stmtCats->fetchAll(PDO::FETCH_ASSOC);


// --- 3. LOGICA FILTRI CARDS ---
$where = [];
$params = [];

$search = isset($_GET['q']) ? trim($_GET['q']) : ''; 
$categoryFilter = isset($_GET['category']) ? (int)$_GET['category'] : 0; 
$privacyFilter = isset($_GET['privacy']) ? $_GET['privacy'] : 'all';

if (!in_array($privacyFilter, ['all', 'public_rw', 'public_r', 'private'], true)) {
    $privacyFilter = 'all';
}

if ($currentRole === 'superuser') {
    $where[] = 'c.owner_id = :owner_id';
    $params['owner_id'] = $currentUserId;
} elseif ($currentRole === 'admin') {
    $where[] = '(c.admin_id = :admin_id OR c.owner_id = :owner_owner_id OR o.created_by = :creator_id)';
    $params['admin_id'] = $currentUserId;
    $params['owner_owner_id'] = $currentUserId;
    $params['creator_id'] = $currentUserId;
} elseif ($currentRole === 'user' && $userAdminId) {
    $where[] = '(c.owner_id = :user_owner_id OR (c.admin_id = :user_admin_id AND c.privacy_level <> "private"))';
    $params['user_owner_id'] = $currentUserId;
    $params['user_admin_id'] = $userAdminId;
} elseif ($currentRole === 'user') {
    $where[] = 'c.owner_id = :fallback_owner_id';
    $params['fallback_owner_id'] = $currentUserId;
}

$where[] = 'c.deleted_at IS NULL';

if ($search !== '') {
    $cleanSearch = str_replace('*', '%', $search);
    $cleanSearch = str_replace('_', '\_', $cleanSearch);
    $like = (strpos($cleanSearch, '%') === false) ? ('%' . $cleanSearch . '%') : $cleanSearch;
    $where[] = "(
        c.name LIKE :like OR
        c.notes LIKE :like OR
        EXISTS (
            SELECT 1 FROM card_entries e2
            WHERE e2.card_id = c.id AND (e2.login LIKE :like OR e2.url LIKE :like OR e2.note LIKE :like)
        )
    )";
    $params['like'] = $like;
}

if ($categoryFilter > 0) {
    $where[] = 'c.category_id = :category_filter';
    $params['category_filter'] = $categoryFilter;
}

if ($privacyFilter !== 'all') {
    $where[] = 'c.privacy_level = :privacy_filter';
    $params['privacy_filter'] = $privacyFilter;
}

$whereSql = '';
if (!empty($where)) {
    $whereSql = 'WHERE ' . implode(' AND ', $where);
}

// Ordinamento
$sortParam = $_GET['sort'] ?? 'name';
$dirParam = strtolower($_GET['dir'] ?? 'asc');
$dir = $dirParam === 'desc' ? 'DESC' : 'ASC';

$sortColumns = [
    'name' => 'c.name',
    'category' => 'cat.name',
    'modified_by' => 'lm.email',
    'created_by' => 'o.email',
    'updated_at' => 'c.updated_at',
];

$currentSort = array_key_exists($sortParam, $sortColumns) ? $sortParam : 'name';
$orderBy = $sortColumns[$currentSort];

// Query principale
$sql = "SELECT 
    c.id, c.name, c.admin_id, c.owner_id, c.privacy_level, c.updated_at, c.last_modified_by, c.category_id,
    o.email AS owner_email, o.created_by AS owner_creator, 
    lm.email AS last_modifier_email, 
    cat.name AS category_name,
    cat.color AS category_color, 
    (SELECT COUNT(1) FROM card_entries ce WHERE ce.card_id = c.id) AS entry_count 
FROM cards c 
JOIN users o ON o.id = c.owner_id 
LEFT JOIN users lm ON lm.id = c.last_modified_by 
LEFT JOIN categories cat ON cat.id = c.category_id 
$whereSql ORDER BY $orderBy $dir";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$cards = $stmt->fetchAll();

function sortLink(string $column, string $label, string $currentSort, string $currentDir, string $search, string $privacy, int $category): string
{
    $nextDir = ($currentSort === $column && $currentDir === 'asc') ? 'desc' : 'asc';
    $query = http_build_query([
        'sort' => $column,
        'dir' => $nextDir,
        'q' => $search,
        'privacy' => $privacy,
        'category' => $category,
    ]);
    $indicator = '';
    if ($currentSort === $column) {
        $indicator = $currentDir === 'desc' ? ' ↓' : ' ↑';
    }
    return '<a class="text-decoration-none" href="cards.php?' . htmlspecialchars($query) . '">' . htmlspecialchars($label) . $indicator . '</a>';
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
    <title>Archivio schede</title>
    <style>
        .actions-nowrap { white-space: nowrap; width: 1%; }
        .action-buttons .btn { margin-left: 2px; }
        .action-buttons form.d-inline { display: inline-block !important; }
        .card-name { display: inline-block; max-width: 40ch; white-space: normal; word-break: break-all; }
        #cardsTable:not(.show-advanced) .advanced-col { display: none; }
        .card-body { position: relative; padding-top: 2rem; }
        .advanced-toggle-container { position: absolute; top: 0.5rem; right: 1rem; z-index: 10; }
        .col-checkbox { width: 40px; text-align: center; }
        
        /* Stile per il badge cliccabile */
        .category-link {
            text-decoration: none;
            color: inherit;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .category-link:hover {
            opacity: 0.8;
        }
    </style>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h1 class="h4 mb-0">Archivio schede</h1>
            <small class="text-muted">Accesso: <?= htmlspecialchars($_SESSION['email'] ?? 'N/A') ?> (<?= htmlspecialchars($_SESSION['role'] ?? 'N/A') ?>)
                <?php if ($impersonating && $impersonatorEmail): ?>
                    <span class="badge bg-warning text-dark ms-2">Impersonato da <?= htmlspecialchars($impersonatorEmail) ?></span>
                <?php endif; ?>
            </small>
        </div>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= htmlspecialchars($messageClass) ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <?php if ($impersonating && $impersonatorEmail): ?>
        <div class="alert alert-warning d-flex align-items-center justify-content-between">
            <div>Stai operando come un altro utente.</div>
            <form method="post" class="mb-0">
                <button class="btn btn-outline-dark btn-sm" type="submit" name="stop_impersonation">Torna al tuo account</button>
            </form>
        </div>
    <?php endif; ?>

    <div class="card shadow-sm">
        <div class="card-body">
            <div class="advanced-toggle-container">
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="toggleAdvancedColumns">
                    <label class="form-check-label" for="toggleAdvancedColumns">Avanzate</label>
                </div>
            </div>

            <form class="row g-2 mb-3 align-items-end" method="get" action="cards.php">
                <div class="col-lg-3 col-md-3">
                    <label class="form-label visually-hidden">Cerca</label>
                    <input type="search" class="form-control" name="q" placeholder="Cerca..." value="<?= htmlspecialchars($search) ?>" aria-label="Cerca">
                </div>

                <div class="col-lg-3 col-md-3">
                    <label class="form-label visually-hidden">Categoria</label>
                    <select class="form-select" name="category" aria-label="Filtra per categoria">
                        <option value="0">Tutte le Categorie</option>
                        <?php foreach ($availableCategories as $cat): ?>
                            <option value="<?= $cat['id'] ?>" <?= $categoryFilter === $cat['id'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($cat['name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="col-lg-3 col-md-3">
                    <label class="form-label visually-hidden">Privacy</label>
                    <select class="form-select" name="privacy" aria-label="Filtra per privacy">
                        <option value="all" <?= $privacyFilter === 'all' ? 'selected' : '' ?>>Tutte le schede</option>
                        <option value="public_rw" <?= $privacyFilter === 'public_rw' ? 'selected' : '' ?>>Pubbliche RW</option>
                        <option value="public_r" <?= $privacyFilter === 'public_r' ? 'selected' : '' ?>>Pubbliche R</option>
                        <option value="private" <?= $privacyFilter === 'private' ? 'selected' : '' ?>>Solo private</option>
                    </select>
                </div>

                <div class="col-lg-3 col-md-3 d-flex gap-2">
                    <button class="btn btn-primary" type="submit">Cerca</button>
                    <a class="btn btn-outline-secondary" href="cards.php">Reset</a>
                    
                    <button type="button" class="btn btn-outline-primary" onclick="openBulkCategoryModal()" title="Assegna categoria ai selezionati">
                        <i class="bi bi-folder-plus"></i>
                    </button>
                </div>
            </form>

            <div id="tableContainer">
                <?php if (empty($cards)): ?>
                    <p class="text-muted mb-0">Nessuna scheda presente.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table align-middle table-striped" id="cardsTable">
                            <thead>
                                <tr>
                                    <th class="col-checkbox">
                                        <input class="form-check-input" type="checkbox" id="selectAllCards">
                                    </th>
                                    <th><?= sortLink('name', 'Nome', $currentSort, $dirParam, $search, $privacyFilter, $categoryFilter) ?></th>
                                    <th><?= sortLink('category', 'Categoria', $currentSort, $dirParam, $search, $privacyFilter, $categoryFilter) ?></th>
                                    <th class="advanced-col"><?= sortLink('created_by', 'Creato da', $currentSort, $dirParam, $search, $privacyFilter, $categoryFilter) ?></th>
                                    <th class="advanced-col"><?= sortLink('updated_at', 'Ultima modifica', $currentSort, $dirParam, $search, $privacyFilter, $categoryFilter) ?></th>
                                    <th class="advanced-col"><?= sortLink('modified_by', 'Modificato da', $currentSort, $dirParam, $search, $privacyFilter, $categoryFilter) ?></th>
                                    <th class="advanced-col">Privacy</th>
                                    <th class="text-end actions-nowrap">Azioni</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($cards as $card): ?>
                                <?php
                                $canEdit = false;
                                $canDelete = false;
                                if ($currentRole === 'superuser') {
                                    $canEdit = (int)$card['owner_id'] === $currentUserId;
                                    $canDelete = $canEdit;
                                } elseif ($currentRole === 'admin') {
                                    $canEdit = (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId || (int)$card['admin_id'] === $currentUserId;
                                    $canDelete = (int)$card['owner_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId;
                                } else {
                                    $isOwner = (int)$card['owner_id'] === $currentUserId;
                                    $isAdminCard = $userAdminId && (
                                        (int)$card['owner_id'] === (int)$userAdminId || 
                                        (int)$card['admin_id'] === (int)$userAdminId
                                    );
                                    $canEdit = $isOwner || ($isAdminCard && $card['privacy_level'] === 'public_rw');
                                    $canDelete = $isOwner;
                                }
                                ?>
                                <tr>
                                    <td class="col-checkbox">
                                        <?php if ($canEdit): ?>
                                            <input class="form-check-input card-checkbox" type="checkbox" value="<?= $card['id'] ?>">
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <a href="card_view.php?id=<?= $card['id'] ?>" class="text-decoration-none">
                                            <span class="card-name" title="<?= htmlspecialchars($card['name']) ?>">
                                                <?= htmlspecialchars($card['name']) ?>
                                            </span>
                                            <?php if ((int)$card['entry_count'] > 1): ?>
                                                <span class="badge bg-secondary ms-1" title="Numero di blocchi credenziali">
                                                    <i class="bi bi-layers"></i> <?= (int)$card['entry_count'] ?>
                                                </span>
                                            <?php endif; ?>
                                        </a>
                                    </td>
                                    
                                    <td>
                                        <?php if (!empty($card['category_name'])): ?>
                                            <?php $catColor = $card['category_color'] ?? '#6c757d'; ?>
                                            <a href="cards.php?category=<?= $card['category_id'] ?>" class="category-link" title="Filtra per questa categoria">
                                                <span class="badge" style="background-color: <?= htmlspecialchars($catColor) ?>; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.5);">
                                                    <?= htmlspecialchars($card['category_name']) ?>
                                                </span>
                                            </a>
                                        <?php else: ?>
                                            <span class="text-muted small">-</span>
                                        <?php endif; ?>
                                    </td>

                                    <td class="advanced-col">&nbsp;<?= htmlspecialchars($card['owner_email'] ?? 'Sconosciuto') ?></td>
                                    <td class="advanced-col small text-muted">
                                        <?= htmlspecialchars(date('Y-m-d H:i', strtotime($card['updated_at']))) ?>
                                    </td>
                                    <td class="advanced-col small text-muted"><?= htmlspecialchars($card['last_modifier_email'] ?? $card['owner_email'] ?? '—') ?></td>
                                    <td class="advanced-col">
                                        <?php if ($card['privacy_level'] === 'private'): ?>
                                            <span class="badge bg-secondary">Privata</span>
                                        <?php elseif ($card['privacy_level'] === 'public_r'): ?>
                                            <span class="badge bg-info">Pubblica R</span>
                                        <?php elseif ($card['privacy_level'] === 'public_rw'): ?>
                                            <span class="badge bg-success-subtle text-success">Pubblica RW</span>
                                        <?php else: ?>
                                            <span class="badge bg-light text-dark border"><?= htmlspecialchars($card['privacy_level'] ?: 'N/D') ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="text-end actions-nowrap">
                                        <div class="action-buttons">
                                            <?php if ($canEdit): ?>
                                                <button type="button" class="btn btn-sm btn-outline-primary" 
                                                        title="Assegna Categoria"
                                                        onclick="openCategoryModal(<?= $card['id'] ?>, '<?= htmlspecialchars(addslashes($card['name'])) ?>', <?= (int)$card['category_id'] ?>)">
                                                    <i class="bi bi-folder-plus"></i>
                                                </button>

                                                <a class="btn btn-sm btn-outline-secondary" href="card_form.php?id=<?= $card['id'] ?>" title="Modifica">
                                                    <i class="bi bi-pencil-square"></i>
                                                </a>
                                            <?php endif; ?>
                                            <?php if ($canDelete): ?>
                                                <?php $confirmMsg = "Vuoi cancellare la scheda \"" . $card['name'] . "\"?"; ?>
                                                <form method="post" class="d-inline" onsubmit='return confirm(<?= json_encode($confirmMsg, JSON_HEX_APOS) ?>);'>
                                                    <input type="hidden" name="delete_id" value="<?= $card['id'] ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-danger" title="Elimina">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="categoryModal" tabindex="-1" aria-labelledby="categoryModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <form method="post" class="modal-content">
      <input type="hidden" name="assign_category_action" value="1">
      <input type="hidden" name="card_id" id="modal_card_id" value="">
      <input type="hidden" name="bulk_card_ids" id="modal_bulk_card_ids" value="">

      <div class="modal-header">
        <h5 class="modal-title" id="categoryModalLabel">Gestione Categoria</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p id="modal_message">Seleziona la categoria:</p>
        
        <div class="mb-3">
            <select class="form-select" name="category_id" id="category_select">
                <option value="0">-- Nessuna Categoria / Rimuovi --</option>
                <?php foreach ($availableCategories as $cat): ?>
                    <option value="<?= $cat['id'] ?>"><?= htmlspecialchars($cat['name']) ?></option>
                <?php endforeach; ?>
                
                <?php if ($currentRole === 'admin' || $currentRole === 'superuser'): ?>
                    <option value="-1" class="fw-bold text-primary">+ Crea Nuova Categoria...</option>
                <?php endif; ?>
            </select>
        </div>

        <div class="mb-3 d-none" id="new_category_group">
            <label for="new_category_name" class="form-label">Nome Nuova Categoria</label>
            <input type="text" class="form-control" name="new_category_name" id="new_category_name" placeholder="Inserisci nome...">
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
        <button type="submit" class="btn btn-success">Salva</button>
      </div>
    </form>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const selectAllCheckbox = document.getElementById('selectAllCards');
if (selectAllCheckbox) {
    selectAllCheckbox.addEventListener('change', function() {
        const checkboxes = document.querySelectorAll('.card-checkbox');
        checkboxes.forEach(cb => cb.checked = this.checked);
    });
}

function openCategoryModal(cardId, cardName, currentCatId) {
    document.getElementById('modal_card_id').value = cardId;
    document.getElementById('modal_bulk_card_ids').value = '';
    document.getElementById('categoryModalLabel').textContent = 'Categoria: ' + cardName;
    document.getElementById('modal_message').innerHTML = 'Modifica categoria:';
    
    const select = document.getElementById('category_select');
    select.value = currentCatId || 0;
    
    document.getElementById('new_category_group').classList.add('d-none');
    document.getElementById('new_category_name').value = '';

    new bootstrap.Modal(document.getElementById('categoryModal')).show();
}

function openBulkCategoryModal() {
    const checkboxes = document.querySelectorAll('.card-checkbox:checked');
    const ids = Array.from(checkboxes).map(cb => cb.value);
    
    if (ids.length === 0) {
        alert("Seleziona almeno una scheda.");
        return;
    }
    
    document.getElementById('modal_card_id').value = '';
    document.getElementById('modal_bulk_card_ids').value = ids.join(',');
    
    document.getElementById('categoryModalLabel').textContent = 'Assegnazione Multipla';
    document.getElementById('modal_message').innerHTML = 'Assegna categoria a <strong>' + ids.length + '</strong> schede:';
    
    document.getElementById('category_select').value = 0; 
    document.getElementById('new_category_group').classList.add('d-none');
    document.getElementById('new_category_name').value = '';

    new bootstrap.Modal(document.getElementById('categoryModal')).show();
}

document.getElementById('category_select').addEventListener('change', function() {
    const newGroup = document.getElementById('new_category_group');
    const input = document.getElementById('new_category_name');
    
    if (this.value === '-1') {
        newGroup.classList.remove('d-none');
        input.focus();
        input.required = true;
    } else {
        newGroup.classList.add('d-none');
        input.required = false;
    }
});

document.addEventListener('DOMContentLoaded', function () {
    const toggle = document.getElementById('toggleAdvancedColumns');
    const table = document.getElementById('cardsTable');
    if (!toggle || !table) return;

    const stored = localStorage.getItem('cards_show_advanced');
    const initial = stored === '1'; 
    toggle.checked = initial;
    if (initial) table.classList.add('show-advanced');

    toggle.addEventListener('change', function () {
        const enabled = toggle.checked;
        table.classList.toggle('show-advanced', enabled);
        localStorage.setItem('cards_show_advanced', enabled ? '1' : '0');
    });
});
</script>
</body>
</html>