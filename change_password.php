<?php
require_once __DIR__ . '/includes/auth.php';
requireLogin();

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';

$errors = [];
$success = null;

$targetId = $currentUserId;
if ($currentRole !== 'user' && isset($_GET['id'])) {
    $targetId = (int)$_GET['id'];
}

$targetUser = getUserById($pdo, $targetId);

// Permission checks: users can change self; admins can change their users; superuser can change all.
$canManageTarget = false;
if ($targetUser) {
    if ($currentRole === 'superuser') {
        $canManageTarget = true;
    } elseif ($currentRole === 'admin') {
        $canManageTarget = ($targetId === $currentUserId) || ($targetUser['role'] === 'user' && (int)$targetUser['created_by'] === $currentUserId);
    } else {
        $canManageTarget = $targetId === $currentUserId;
    }
}

if (!$targetUser || !$canManageTarget) {
    http_response_code(403);
    echo 'Accesso negato.';
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $currentPassword = $_POST['current_password'] ?? '';

    if ($targetId === $currentUserId && !password_verify($currentPassword, $currentUser['password_hash'])) {
        $errors[] = 'Password attuale non corretta.';
    }
    if (!isPasswordComplex($newPassword)) {
        $errors[] = 'La password deve avere almeno 6 caratteri e includere una lettera, un numero e un carattere speciale.';
    }
    if ($newPassword !== $confirmPassword) {
        $errors[] = 'Le password non coincidono.';
    }

    if (!$errors) {
        $stmt = $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $stmt->execute([password_hash($newPassword, PASSWORD_DEFAULT), $targetId]);
        $success = 'Password aggiornata con successo.';
        if ($targetId === $currentUserId) {
            $currentUser = getUserById($pdo, $currentUserId);
        }
    }
}

// Build list of selectable targets for admins/superusers.
$managedUsers = [];
if ($currentRole === 'superuser') {
    $managedUsers = $pdo->query("SELECT id, email FROM users ORDER BY email")->fetchAll();
} elseif ($currentRole === 'admin') {
    $stmt = $pdo->prepare('SELECT id, email FROM users WHERE id = ? OR (created_by = ? AND role = "user") ORDER BY email');
    $stmt->execute([$currentUserId, $currentUserId]);
    $managedUsers = $stmt->fetchAll();
}
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title>Cambia password</title>
</head>
<body>
<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0">Cambia password</h1>
        <div>
            <a href="cards.php" class="btn btn-link">Torna alle schede</a>
            <a href="logout.php" class="btn btn-link">Logout</a>
        </div>
    </div>

    <?php if ($success): ?>
        <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
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

    <?php if ($managedUsers && $currentRole !== 'user'): ?>
        <form method="get" class="row g-2 mb-4" autocomplete="off">
            <div class="col-md-8">
                <label class="form-label mb-1" for="id">Seleziona utente</label>
                <select name="id" id="id" class="form-select">
                    <?php foreach ($managedUsers as $user): ?>
                        <option value="<?= $user['id'] ?>" <?= $targetId === (int)$user['id'] ? 'selected' : '' ?>><?= htmlspecialchars($user['email']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-4 d-flex align-items-end">
                <button type="submit" class="btn btn-outline-secondary w-100">Cambia destinatario</button>
            </div>
        </form>
    <?php endif; ?>

    <div class="card">
        <div class="card-body">
            <h2 class="h6">Aggiorna password per <?= htmlspecialchars($targetUser['email']) ?></h2>
            <form method="post" class="row g-3" autocomplete="off">
                <?php if ($targetId === $currentUserId): ?>
                    <div class="col-md-6">
                        <label class="form-label">Password attuale</label>
                        <input type="password" name="current_password" class="form-control" autocomplete="current-password" required>
                    </div>
                <?php endif; ?>
                <div class="col-md-6">
                    <label class="form-label">Nuova password</label>
                    <input type="password" name="new_password" class="form-control" autocomplete="new-password" required>
                </div>
                <div class="col-md-6">
                    <label class="form-label">Conferma password</label>
                    <input type="password" name="confirm_password" class="form-control" autocomplete="new-password" required>
                </div>
                <div class="col-12 d-flex justify-content-end gap-2">
                    <a href="cards.php" class="btn btn-outline-secondary">Annulla</a>
                    <button type="submit" class="btn btn-primary">Aggiorna password</button>
                </div>
            </form>
        </div>
    </div>
</div>
</body>
</html>