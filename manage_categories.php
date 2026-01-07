<?php
require_once __DIR__ . '/includes/auth.php';
requireRole('admin'); // Accesso consentito solo ad Admin (e Superuser)

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$adminScopeId = $currentUserId;

$errors = [];
$success = null;
$categoryToEdit = null;

// Colore predefinito (Azzurro del tema)
$defaultColor = '#1e88e5';

// --- 1. GESTIONE MODALITÀ MODIFICA (GET) ---
if (isset($_GET['edit'])) {
    $editId = (int)$_GET['edit'];
    $stmt = $pdo->prepare("SELECT * FROM categories WHERE id = ? AND created_by_admin = ?");
    $stmt->execute([$editId, $adminScopeId]);
    $categoryToEdit = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$categoryToEdit) {
        $errors[] = "Categoria non trovata o non autorizzata.";
    }
}

// --- 2. GESTIONE POST (Crea / Modifica / Elimina) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // A. CREA CATEGORIA
    if (isset($_POST['create_category'])) {
        $catName = trim($_POST['name'] ?? '');
        // Usa l'azzurro come default se non specificato
        $catColor = $_POST['color'] ?? $defaultColor; 
        
        if (strlen($catName) < 2) {
            $errors[] = 'Il nome della categoria deve avere almeno 2 caratteri.';
        } else {
            // Verifica duplicati
            $stmtCheck = $pdo->prepare("SELECT id FROM categories WHERE name = ? AND created_by_admin = ?");
            $stmtCheck->execute([$catName, $adminScopeId]);
            if ($stmtCheck->fetch()) {
                $errors[] = 'Hai già creato una categoria con questo nome.';
            } else {
                // Inserimento con colore
                $stmt = $pdo->prepare("INSERT INTO categories (name, color, created_by_admin) VALUES (?, ?, ?)");
                if ($stmt->execute([$catName, $catColor, $adminScopeId])) {
                    $success = 'Categoria creata con successo.';
                } else {
                    $errors[] = 'Errore database durante la creazione.';
                }
            }
        }
    }
    
    // B. AGGIORNA CATEGORIA
    elseif (isset($_POST['update_category'])) {
        $catId = (int)$_POST['id'];
        $catName = trim($_POST['name'] ?? '');
        $catColor = $_POST['color'] ?? $defaultColor;
        
        if (strlen($catName) < 2) {
            $errors[] = 'Il nome deve avere almeno 2 caratteri.';
        } else {
            // Aggiornamento con colore
            $stmt = $pdo->prepare("UPDATE categories SET name = ?, color = ? WHERE id = ? AND created_by_admin = ?");
            if ($stmt->execute([$catName, $catColor, $catId, $adminScopeId])) {
                header('Location: manage_categories.php?msg=updated');
                exit;
            } else {
                $errors[] = 'Errore durante l\'aggiornamento.';
            }
        }
    }
    
    // C. ELIMINA CATEGORIA
    elseif (isset($_POST['delete_id'])) {
        $delId = (int)$_POST['delete_id'];
        $stmtCheck = $pdo->prepare("SELECT id FROM categories WHERE id = ? AND created_by_admin = ?");
        $stmtCheck->execute([$delId, $adminScopeId]);
        if ($stmtCheck->fetch()) {
            $stmt = $pdo->prepare("DELETE FROM categories WHERE id = ?");
            $stmt->execute([$delId]);
            $success = 'Categoria eliminata.';
            if ($categoryToEdit && (int)$categoryToEdit['id'] === $delId) {
                $categoryToEdit = null;
            }
        } else {
            $errors[] = 'Impossibile eliminare: categoria non trovata.';
        }
    }
}

if (isset($_GET['msg']) && $_GET['msg'] === 'updated') {
    $success = "Categoria aggiornata con successo.";
}

// --- 3. RECUPERO LISTA CATEGORIE ---
$stmt = $pdo->prepare("
    SELECT c.*, 
    (SELECT COUNT(*) FROM cards WHERE category_id = c.id AND deleted_at IS NULL) as card_count 
    FROM categories c 
    WHERE c.created_by_admin = ? 
    ORDER BY c.name ASC
");
$stmt->execute([$adminScopeId]);
$categories = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <link href="assets/style.css" rel="stylesheet">
    <title>Gestione Categorie</title>
    <style>
        /* Stile per il selettore colore per renderlo più gradevole */
        .color-input {
            height: 38px;
            padding: 4px;
            cursor: pointer;
        }
        /* Pallino colorato nella lista */
        .cat-dot {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
            border: 1px solid rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0">Gestione Categorie</h1>
    </div>

    <?php if ($success): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($success) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>
    <?php if ($errors): ?>
        <div class="alert alert-danger">
            <ul class="mb-0">
                <?php foreach ($errors as $error): ?>
                    <li><?= htmlspecialchars($error) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <div class="row g-4">
        <div class="col-md-4">
            <div class="card shadow-sm h-100">
                <div class="card-body">
                    <h2 class="h6 mb-3">
                        <?= $categoryToEdit ? 'Modifica Categoria' : 'Nuova Categoria' ?>
                    </h2>
                    
                    <form method="post" autocomplete="off">
                        <?php if ($categoryToEdit): ?>
                            <input type="hidden" name="update_category" value="1">
                            <input type="hidden" name="id" value="<?= $categoryToEdit['id'] ?>">
                        <?php else: ?>
                            <input type="hidden" name="create_category" value="1">
                        <?php endif; ?>

                        <div class="mb-3">
                            <label class="form-label">Nome</label>
                            <input type="text" name="name" class="form-control" 
                                   placeholder="Es. Server, Social..." 
                                   value="<?= htmlspecialchars($categoryToEdit['name'] ?? '') ?>" 
                                   required>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Colore Etichetta</label>
                            <input type="color" name="color" class="form-control form-control-color w-100 color-input" 
                                   value="<?= htmlspecialchars($categoryToEdit['color'] ?? $defaultColor) ?>" 
                                   title="Scegli un colore per la categoria">
                        </div>

                        <div class="d-grid gap-2">
                            <button type="submit" class="btn <?= $categoryToEdit ? 'btn-warning' : 'btn-primary' ?>">
                                <?= $categoryToEdit ? 'Salva Modifiche' : 'Crea' ?>
                            </button>
                            
                            <?php if ($categoryToEdit): ?>
                                <a href="manage_categories.php" class="btn btn-outline-secondary">Annulla</a>
                            <?php endif; ?>
                        </div>
                    </form>
                    
                    <?php if (!$categoryToEdit): ?>
                    <p class="small text-muted mt-3">
                        Puoi assegnare un colore per distinguere visivamente le schede nella lista principale.
                    </p>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="col-md-8">
            <div class="card shadow-sm h-100">
                <div class="card-body">
                    <h2 class="h6 mb-3">Le tue Categorie</h2>
                    
                    <?php if (empty($categories)): ?>
                        <p class="text-muted">Nessuna categoria presente.</p>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table align-middle table-hover">
                                <thead>
                                    <tr>
                                        <th>Nome</th>
                                        <th class="text-center">Schede</th>
                                        <th class="text-end" style="min-width: 100px;">Azioni</th>
                                    </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($categories as $cat): ?>
                                    <?php 
                                        // Fallback al colore di default se nullo
                                        $color = $cat['color'] ?? $defaultColor; 
                                    ?>
                                    <tr class="<?= ($categoryToEdit && $cat['id'] == $categoryToEdit['id']) ? 'table-active' : '' ?>">
                                        <td>
                                            <span class="cat-dot" style="background-color: <?= htmlspecialchars($color) ?>;"></span>
                                            <strong><?= htmlspecialchars($cat['name']) ?></strong>
                                        </td>
                                        <td class="text-center">
                                            <span class="badge <?= $cat['card_count'] > 0 ? 'bg-info text-dark' : 'bg-light text-secondary' ?>">
                                                <?= $cat['card_count'] ?>
                                            </span>
                                        </td>
                                        <td class="text-end">
                                            <a href="manage_categories.php?edit=<?= $cat['id'] ?>" class="btn btn-sm btn-outline-secondary" title="Modifica">
                                                <i class="bi bi-pencil"></i>
                                            </a>

                                            <form method="post" class="d-inline" onsubmit="return confirm('Eliminare la categoria \'<?= htmlspecialchars(addslashes($cat['name'])) ?>\'? Le schede collegate perderanno la categoria.');">
                                                <input type="hidden" name="delete_id" value="<?= $cat['id'] ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger" title="Elimina">
                                                    <i class="bi bi-trash"></i>
                                                </button>
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
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>