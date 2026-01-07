<?php
require_once __DIR__ . '/includes/auth.php';
requireLogin();

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';
$userAdminId = $currentUser['created_by'] ?? null;

$message = null;
$messageClass = 'success';

function cardScopeWhere(string $role, int $currentUserId, ?int $userAdminId): array
{
    $where = ['c.deleted_at IS NOT NULL'];
    $params = [];

    if ($role === 'superuser') {
        $where[] = 'c.owner_id = ?';
        $params[] = $currentUserId;
    } elseif ($role === 'admin') {
        $where[] = '(c.owner_id = ? OR o.created_by = ?)';
        $params[] = $currentUserId;
        $params[] = $currentUserId;
    } else {
        $where[] = 'c.deleted_by = ?';
        $params[] = $currentUserId;
    }

    return [$where, $params];
}

function canAdministerCard(array $card, string $role, int $currentUserId): bool
{
    if (roleLevel($role) < roleLevel('admin')) {
        return false;
    }
    if ($role === 'superuser') {
        return (int)$card['owner_id'] === $currentUserId;
    }
    return (int)$card['owner_id'] === $currentUserId || (int)$card['admin_id'] === $currentUserId || (int)$card['owner_creator'] === $currentUserId;
}

function canRestoreCard(array $card, string $role, int $currentUserId): bool
{
    if ((int)$card['deleted_by'] === $currentUserId) {
        return true;
    }
    return canAdministerCard($card, $role, $currentUserId);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if (in_array($action, ['restore', 'purge'], true) && isset($_POST['card_id'])) {
        $cardId = (int)$_POST['card_id'];
        $stmt = $pdo->prepare('SELECT c.*, o.created_by AS owner_creator FROM cards c JOIN users o ON o.id = c.owner_id WHERE c.id = ? AND c.deleted_at IS NOT NULL');
        $stmt->execute([$cardId]);
        $card = $stmt->fetch();

        if ($card) {
            if ($action === 'restore' && canRestoreCard($card, $currentRole, $currentUserId)) {
                $stmt = $pdo->prepare('UPDATE cards SET deleted_at = NULL, deleted_by = NULL, restored_at = NOW(), restored_by = ?, updated_at = NOW(), last_modified_by = ? WHERE id = ?');
                $stmt->execute([$currentUserId, $currentUserId, $cardId]);
                $message = 'Scheda ripristinata con successo.';
                $messageClass = 'success';
            } elseif ($action === 'purge' && canAdministerCard($card, $currentRole, $currentUserId)) {
                $pdo->prepare('DELETE FROM card_entries WHERE card_id = ?')->execute([$cardId]);
                $pdo->prepare('DELETE FROM cards WHERE id = ?')->execute([$cardId]);
                $message = 'Scheda rimossa definitivamente.';
                $messageClass = 'success';
            }
        } else {
             $message = 'Operazione non autorizzata o scheda non trovata.';
             $messageClass = 'danger';
        }
    }

    if ($action === 'empty' && roleLevel($currentRole) >= roleLevel('admin')) {
        [$scopeWhere, $scopeParams] = cardScopeWhere($currentRole, $currentUserId, $userAdminId);
        $whereSql = 'WHERE ' . implode(' AND ', $scopeWhere);
        $stmt = $pdo->prepare("SELECT c.id FROM cards c JOIN users o ON o.id = c.owner_id $whereSql");
        $stmt->execute($scopeParams);
        $ids = array_column($stmt->fetchAll(), 'id');
        if (!empty($ids)) {
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $pdo->prepare("DELETE FROM cards WHERE id IN ($placeholders)")->execute($ids);
        }
        $message = 'Cestino svuotato.';
        $messageClass = 'success';
    }
}

[$where, $params] = cardScopeWhere($currentRole, $currentUserId, $userAdminId);
$whereSql = 'WHERE ' . implode(' AND ', $where);

$stmt = $pdo->prepare("
    SELECT c.id, c.name, c.notes, c.admin_id, c.owner_id, c.deleted_at, c.deleted_by, c.restored_at, c.restored_by, c.privacy_level, 
           o.email AS owner_email, o.created_by AS owner_creator, d.email AS deleter_email, r.email AS restorer_email 
    FROM cards c 
    JOIN users o ON o.id = c.owner_id 
    LEFT JOIN users d ON d.id = c.deleted_by 
    LEFT JOIN users r ON r.id = c.restored_by 
    $whereSql 
    ORDER BY c.deleted_at DESC
");
$stmt->execute($params);
$trashedCards = $stmt->fetchAll();
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title>Cestino schede</title>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h1 class="h4 mb-0">Cestino schede</h1>
            <small class="text-muted">Accesso: <?= htmlspecialchars($_SESSION['email'] ?? 'N/A') ?> (<?= htmlspecialchars($_SESSION['role'] ?? 'N/A') ?>)</small>
        </div>
        <div>
            <?php 
            if (roleLevel($currentRole) >= roleLevel('admin') && !empty($trashedCards)): 
            ?>
                <form method="post" class="d-inline" onsubmit="return confirm('Svuotare il cestino? L\'operazione è irreversibile e rimuoverà tutte le schede visibili.');">
                    <input type="hidden" name="action" value="empty">
                    <button type="submit" class="btn btn-danger btn-sm">Svuota cestino</button>
                </form>
            <?php endif; ?>
        </div>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= htmlspecialchars($messageClass) ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div class="card shadow-sm">
        <div class="card-body">
            <?php if (empty($trashedCards)): ?>
                <p class="text-muted mb-0">Il cestino è vuoto.</p>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table align-middle">
                        <thead>
                        <tr>
                            <th>Nome</th>
                            <th>Creato da</th>
                            <th>Privacy</th>
                            <th>Cancellato il</th>
                            <th>Cancellato da</th>
                            <th>Ripristinato da</th>
                            <th class="text-end">Azioni</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($trashedCards as $card): ?>
                            <tr>
                                <td><?= htmlspecialchars($card['name']) ?></td>
                                <td><?= htmlspecialchars($card['owner_email'] ?? 'Sconosciuto') ?></td>
                                <td>
                                    <?php if ($card['privacy_level'] === 'private'): ?>
                                        <span class="badge bg-secondary">Privata</span>
                                    <?php elseif ($card['privacy_level'] === 'public_r'): ?>
                                        <span class="badge bg-info">Pubblica R</span>
                                    <?php else: ?>
                                        <span class="badge bg-success-subtle text-success">Pubblica RW</span>
                                    <?php endif; ?>
                                </td>
                                <td class="small text-muted"><?= htmlspecialchars($card['deleted_at'] ? date('Y-m-d H:i', strtotime($card['deleted_at'])) : '-') ?></td>
                                <td class="small text-muted"><?= htmlspecialchars($card['deleter_email'] ?? '-') ?></td>
                                <td class="small text-muted">
                                    <?php if ($card['restorer_email'] && $card['restored_at']): ?>
                                        <?= htmlspecialchars(date('Y-m-d H:i', strtotime($card['restored_at']))) ?> da <?= htmlspecialchars($card['restorer_email']) ?>
                                    <?php else: ?>
                                        -
                                    <?php endif; ?>
                                </td>
                                <td class="text-end">
                                    <?php
                                    $canRestore = canRestoreCard($card, $currentRole, $currentUserId);
                                    $canPurge = roleLevel($currentRole) >= roleLevel('admin') && canAdministerCard($card, $currentRole, $currentUserId);
                                    ?>
                                    <div class="d-flex gap-1 justify-content-end">
                                        <?php if ($canRestore): ?>
                                            <form method="post" class="d-inline" onsubmit="return confirm('Ripristinare la scheda?');">
                                                <input type="hidden" name="action" value="restore">
                                                <input type="hidden" name="card_id" value="<?= $card['id'] ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-primary" title="Ripristina">
                                                    <i class="bi bi-arrow-counterclockwise"></i>
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                        <?php if ($canPurge): ?>
                                            <form method="post" class="d-inline" onsubmit="return confirm('Eliminare definitivamente la scheda? L\'operazione è irreversibile.');">
                                                <input type="hidden" name="action" value="purge">
                                                <input type="hidden" name="card_id" value="<?= $card['id'] ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger" title="Elimina Definitivamente">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                    <?php if (!$canRestore && !$canPurge): ?>
                                        <span class="text-muted small">Nessuna azione</span>
                                    <?php endif; ?>
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

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>