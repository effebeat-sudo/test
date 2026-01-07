<?php
require_once __DIR__ . '/includes/auth.php';
requireLogin();

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';
$userAdminId = $currentUser['created_by'] ?? null;

// 1. Determina di chi dobbiamo vedere le categorie
$adminIdForCats = ($currentRole === 'user') ? ($userAdminId ?? 0) : $currentUserId;

// 2. Recupera le categorie con il conteggio e il COLORE (AGGIORNATO)
$stmt = $pdo->prepare("
    SELECT cat.id, cat.name, cat.color,
           (SELECT COUNT(*) FROM cards c WHERE c.category_id = cat.id AND c.deleted_at IS NULL) as card_count
    FROM categories cat 
    WHERE cat.created_by_admin = ? 
    ORDER BY cat.name ASC
");
$stmt->execute([$adminIdForCats]);
$categories = $stmt->fetchAll(PDO::FETCH_ASSOC);

// 3. LOGICA DI REINDIRIZZAMENTO
// Se non ci sono categorie, vai direttamente alla lista schede
if (empty($categories)) {
    header('Location: cards.php');
    exit;
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
    <title>Home - Categorie</title>
    <style>
        .cat-card {
            transition: transform 0.2s, box-shadow 0.2s;
            cursor: pointer;
            border: 1px solid var(--border);
            border-left-width: 6px; /* Bordo sinistro più spesso per il colore */
            text-decoration: none;
            color: inherit;
            display: block;
            background-color: #fff;
        }
        .cat-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-hover);
            background-color: var(--background-azure);
        }
        .cat-icon {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        .cat-count {
            font-size: 0.9rem;
            color: var(--text-muted);
        }
        /* Stile specifico per il bottone 'Nuova Scheda' */
        .cat-card-new {
            border: 2px dashed #ccc;
            border-left-width: 2px;
            background-color: rgba(0,0,0,0.01);
        }
        .cat-card-new:hover {
            border-color: var(--primary-500);
            background-color: #fff;
        }
    </style>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h1 class="h4 mb-0">Benvenuto, <?= htmlspecialchars($currentUser['email']) ?></h1>
            <p class="text-muted small mb-0">Seleziona una categoria per visualizzare le schede</p>
        </div>
    </div>

    <div class="row g-4">
        
        <div class="col-6 col-md-4 col-lg-3">
            <a href="cards.php" class="card h-100 shadow-sm cat-card text-center p-4" style="border-left-color: var(--primary-500);">
                <div class="cat-icon" style="color: var(--primary-500);"><i class="bi bi-grid-fill"></i></div>
                <h5 class="card-title mb-1">Tutte</h5>
                <span class="cat-count">Elenco completo</span>
            </a>
        </div>

        <?php foreach ($categories as $cat): ?>
            <?php 
                $catColor = $cat['color'] ?? '#6c757d'; // Fallback grigio
            ?>
            <div class="col-6 col-md-4 col-lg-3">
                <a href="cards.php?category=<?= $cat['id'] ?>" 
                   class="card h-100 shadow-sm cat-card text-center p-4"
                   style="border-left-color: <?= htmlspecialchars($catColor) ?>;">
                    
                    <div class="cat-icon" style="color: <?= htmlspecialchars($catColor) ?>;">
                        <i class="bi bi-folder-fill"></i>
                    </div>
                    
                    <h5 class="card-title mb-1 text-truncate" title="<?= htmlspecialchars($cat['name']) ?>">
                        <?= htmlspecialchars($cat['name']) ?>
                    </h5>
                    <span class="cat-count"><?= $cat['card_count'] ?> schede</span>
                </a>
            </div>
        <?php endforeach; ?>

        <div class="col-6 col-md-4 col-lg-3">
            <a href="card_form.php" class="card h-100 shadow-sm cat-card cat-card-new text-center p-4">
                <div class="cat-icon text-success"><i class="bi bi-plus-circle"></i></div>
                <h5 class="card-title mb-1 text-success">Nuova Scheda</h5>
                <span class="cat-count">Aggiungi voce</span>
            </a>
        </div>

    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>