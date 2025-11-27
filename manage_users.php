<?php
require_once __DIR__ . '/includes/auth.php';
requireRole('admin');

$errors = [];
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['create_user'])) {
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? 'user';

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Email non valida.';
        }
        if (strlen($password) < 6) {
            $errors[] = 'La password deve contenere almeno 6 caratteri.';
        }
        if (roleLevel($_SESSION['role']) < roleLevel($role)) {
            $errors[] = 'Non puoi creare un ruolo superiore al tuo.';
        }

        if (!$errors) {
            $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $errors[] = 'Email già registrata.';
            } else {
                $stmt = $pdo->prepare('INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, NOW())');
                $stmt->execute([$email, password_hash($password, PASSWORD_DEFAULT), $role]);
                $success = 'Utente creato con successo.';
            }
        }
    } elseif (isset($_POST['delete_id'])) {
        $deleteId = (int)$_POST['delete_id'];
        $target = getUserById($pdo, $deleteId);
        if ($target) {
            if ($target['role'] === 'superuser') {
                $errors[] = 'Non puoi eliminare il superuser.';
            } elseif ($_SESSION['role'] === 'admin' && $target['role'] !== 'user') {
                $errors[] = 'Gli admin possono eliminare solo utenti standard.';
            } elseif ($deleteId === (int)$_SESSION['user_id']) {
                $errors[] = 'Non puoi eliminare te stesso.';
            } else {
                $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$deleteId]);
                $success = 'Utente eliminato.';
            }
        }
    }
}

$stmt = $pdo->query('SELECT id, email, role, created_at FROM users ORDER BY created_at DESC');
$users = $stmt->fetchAll();
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title>Gestione utenti</title>
</head>
<body>
<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4">Gestione utenti</h1>
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

    <div class="card mb-4">
        <div class="card-body">
            <h2 class="h6">Crea nuovo utente</h2>
            <form method="post" class="row g-3">
                <div class="col-md-4">
                    <label class="form-label">Email</label>
                    <input type="email" name="email" class="form-control" required>
                </div>
                <div class="col-md-4">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                <div class="col-md-3">
                    <label class="form-label">Ruolo</label>
                    <select name="role" class="form-select">
                        <option value="user">Utente</option>
                        <?php if ($_SESSION['role'] === 'superuser'): ?>
                            <option value="admin">Admin</option>
                        <?php endif; ?>
                    </select>
                </div>
                <div class="col-md-1 d-flex align-items-end">
                    <button type="submit" name="create_user" class="btn btn-primary w-100">Crea</button>
                </div>
            </form>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <h2 class="h6">Utenti esistenti</h2>
            <div class="table-responsive">
                <table class="table align-middle">
                    <thead>
                        <tr>
                            <th>Email</th>
                            <th>Ruolo</th>
                            <th>Creato il</th>
                            <th class="text-end">Azioni</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?= htmlspecialchars($user['email']) ?></td>
                            <td><?= htmlspecialchars($user['role']) ?></td>
                            <td><?= htmlspecialchars($user['created_at']) ?></td>
                            <td class="text-end">
                                <?php if ($user['id'] !== (int)$_SESSION['user_id']): ?>
                                    <form method="post" class="d-inline" onsubmit="return confirm('Eliminare questo utente?');">
                                        <input type="hidden" name="delete_id" value="<?= $user['id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger">Elimina</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
</body>
</html>
