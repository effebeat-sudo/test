<?php
require_once __DIR__ . '/includes/auth.php';
requireLogin();

$message = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    $deleteId = (int)$_POST['delete_id'];
    $stmt = $pdo->prepare('DELETE FROM card_entries WHERE card_id = ?');
    $stmt->execute([$deleteId]);
    $stmt = $pdo->prepare('DELETE FROM cards WHERE id = ?');
    $stmt->execute([$deleteId]);
    $message = 'Scheda eliminata con successo.';
}

$stmt = $pdo->query('SELECT c.id, c.name, c.notes, COUNT(e.id) as entries FROM cards c LEFT JOIN card_entries e ON e.card_id = c.id GROUP BY c.id ORDER BY c.created_at DESC');
$cards = $stmt->fetchAll();
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title>Schede salvate</title>
</head>
<body>
<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h1 class="h4 mb-0">Archivio schede</h1>
            <small class="text-muted">Accesso: <?= htmlspecialchars($_SESSION['email']) ?> (<?= htmlspecialchars($_SESSION['role']) ?>)</small>
        </div>
        <div>
            <a href="manage_users.php" class="btn btn-outline-secondary btn-sm<?= roleLevel($_SESSION['role']) < 2 ? ' disabled' : '' ?>">Gestione utenti</a>
            <a href="card_form.php" class="btn btn-primary">Nuova scheda</a>
            <a href="logout.php" class="btn btn-link">Logout</a>
        </div>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div class="card shadow-sm">
        <div class="card-body">
            <?php if (empty($cards)): ?>
                <p class="text-muted mb-0">Nessuna scheda presente.</p>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table align-middle">
                        <thead>
                            <tr>
                                <th>Nome</th>
                                <th>Credenziali salvate</th>
                                <th>Note</th>
                                <th class="text-end">Azioni</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($cards as $card): ?>
                            <tr>
                                <td><?= htmlspecialchars($card['name']) ?></td>
                                <td><?= (int)$card['entries'] ?></td>
                                <td class="text-muted small"><?= nl2br(htmlspecialchars(substr($card['notes'], 0, 60))) ?></td>
                                <td class="text-end">
                                    <a class="btn btn-sm btn-outline-primary" href="card_view.php?id=<?= $card['id'] ?>">Apri</a>
                                    <a class="btn btn-sm btn-outline-secondary" href="card_form.php?id=<?= $card['id'] ?>">Modifica</a>
                                    <form method="post" class="d-inline" onsubmit="return confirm('Eliminare la scheda?');">
                                        <input type="hidden" name="delete_id" value="<?= $card['id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger">Elimina</button>
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
</body>
</html>
