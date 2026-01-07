<?php
require_once __DIR__ . '/includes/auth.php';
requireRole('admin');

$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';

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
        if (!isPasswordComplex($password)) {
            $errors[] = 'La password deve avere almeno 6 caratteri e includere una lettera, un numero e un carattere speciale.';
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
                $stmt = $pdo->prepare('INSERT INTO users (email, password_hash, role, created_by, created_at) VALUES (?, ?, ?, ?, NOW())');
                $stmt->execute([$email, password_hash($password, PASSWORD_DEFAULT), $role, $currentUserId]);
                $success = 'Utente creato con successo.';
            }
        }
    } elseif (isset($_POST['update_password'])) {
        $targetId = (int)($_POST['user_id'] ?? 0);
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        $target = getUserById($pdo, $targetId);

        if (!$target) {
            $errors[] = 'Utente non trovato.';
        } elseif ($currentRole === 'admin' && $targetId !== $currentUserId && ($target['role'] !== 'user' || (int)$target['created_by'] !== $currentUserId)) {
            $errors[] = 'Puoi aggiornare la password solo dei tuoi utenti.';
        } elseif ($target['role'] === 'superuser' && $currentRole !== 'superuser') {
            $errors[] = 'Non puoi modificare la password del superuser.';
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
            $success = 'Password aggiornata.';
        }
    } elseif (isset($_POST['delete_id'])) {
        $deleteId = (int)$_POST['delete_id'];
        $target = getUserById($pdo, $deleteId);
        
        if ($target) {
            if ($target['role'] === 'superuser') {
                $errors[] = 'Non puoi eliminare il superuser.';
            } elseif ($currentRole === 'admin' && $target['role'] === 'admin') {
                 $errors[] = 'Solo il superuser può eliminare un altro admin.';
            } elseif ($currentRole === 'admin' && ($target['role'] !== 'user' || (int)$target['created_by'] !== $currentUserId)) {
                $errors[] = 'Gli admin possono eliminare solo i propri utenti standard.';
            } elseif ($deleteId === (int)$_SESSION['user_id']) {
                $errors[] = 'Non puoi eliminare te stesso.';
            } else {
                try {
                    $pdo->beginTransaction();

                    $managedUsers = [];
                    $reassignCards = false;
                    $deleteCards = true;

                    if ($target['role'] === 'admin') {
                        $stmt = $pdo->prepare('SELECT id FROM users WHERE created_by = ?');
                        $stmt->execute([$deleteId]);
                        $managedUsers = array_column($stmt->fetchAll(), 'id');
                        $deleteCards = true;
                    } elseif ($target['role'] === 'user') {
                        $reassignCards = true; 
                        $deleteCards = false; 
                    }

                    $ownerIds = array_merge([$deleteId], $managedUsers);

                    if ($reassignCards) {
                        // Utente Standard eliminato: Riassegna le schede all'Admin corrente
                        $reassignSql = 'UPDATE cards SET owner_id = ?, last_modified_by = ? WHERE owner_id = ?';
                        $stmt = $pdo->prepare($reassignSql);
                        $stmt->execute([$currentUserId, $currentUserId, $deleteId]);
                        $success = 'Utente eliminato. Schede riassegnate al tuo account.';
                        
                    } elseif ($deleteCards && $ownerIds) {
                        // Admin eliminato (da Superuser): DELETE totale
                        $placeholders = implode(',', array_fill(0, count($ownerIds), '?'));
                        $deleteCardsSql = "DELETE FROM cards WHERE admin_id = ? OR owner_id IN ($placeholders)";
                        $stmt = $pdo->prepare($deleteCardsSql);
                        $stmt->execute(array_merge([$deleteId], $ownerIds));
                        $success = 'Admin eliminato con i relativi utenti e schede.';
                    }

                    // Cancella gli utenti gestiti
                    if (!empty($managedUsers)) {
                        $placeholders = implode(',', array_fill(0, count($managedUsers), '?'));
                        $pdo->prepare("DELETE FROM users WHERE id IN ($placeholders)")->execute($managedUsers);
                    }

                    // Cancella l'utente target
                    $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$deleteId]);

                    $pdo->commit();
                    if (!$success) {
                        $success = 'Utente eliminato con successo.';
                    }
                } catch (Exception $e) {
                    $pdo->rollBack();
                    $errors[] = 'Errore durante l\'eliminazione: ' . $e->getMessage();
                }
            }
        }
    }
}

if ($currentRole === 'superuser') {
    $stmt = $pdo->prepare('SELECT id, email, role, created_at, created_by FROM users ORDER BY created_at DESC');
    $stmt->execute();
} else {
    $stmt = $pdo->prepare('SELECT id, email, role, created_at, created_by FROM users WHERE id = ? OR created_by = ? ORDER BY created_at DESC');
    $stmt->execute([$currentUserId, $currentUserId]);
}
$users = $stmt->fetchAll();

$creators = [];
if ($users) {
    $creatorIds = array_unique(array_filter(array_column($users, 'created_by')));
    if ($creatorIds) {
        $creatorIds = array_values($creatorIds);
        $in = implode(',', array_fill(0, count($creatorIds), '?'));
        $stmt = $pdo->prepare("SELECT id, email FROM users WHERE id IN ($in)");
        $stmt->execute($creatorIds);
        foreach ($stmt->fetchAll() as $row) {
            $creators[$row['id']] = $row['email'];
        }
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
    <title>Gestione utenti</title>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4">Gestione utenti</h1>
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

    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <h2 class="h6">Crea nuovo utente</h2>
            <form method="post" class="row g-3 align-items-end" autocomplete="off">
                <div class="col-md-3"> 
                    <label class="form-label">Email</label>
                    <input type="email" name="email" class="form-control" autocomplete="off" required>
                </div>
                <div class="col-md-3">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control" autocomplete="new-password" required>
                </div>
                <div class="col-md-4">
                    <label class="form-label">Ruolo</label>
                    <select name="role" class="form-select">
                        <option value="user">Utente</option>
                        <?php if ($_SESSION['role'] === 'superuser'): ?>
                            <option value="admin">Admin</option>
                        <?php endif; ?>
                    </select>
                </div>
                <div class="col-md-2 d-flex align-items-end">
                    <button type="submit" name="create_user" class="btn btn-primary w-100">Crea</button>
                </div>
            </form>
        </div>
    </div>

    <div class="card shadow-sm">
        <div class="card-body">
            <h2 class="h6">Utenti esistenti</h2>
            <div class="table-responsive">
                <table class="table align-middle">
                    <thead>
                        <tr>
                            <th>Email</th>
                            <th>Ruolo</th>
                            <th>Creato da</th>
                            <th>Creato il</th>
                            <th class="text-end">Azioni</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?= htmlspecialchars($user['email']) ?></td>
                            <td><?= htmlspecialchars($user['role']) ?></td>
                            <td><?= htmlspecialchars($creators[$user['created_by']] ?? ($user['created_by'] ? 'Sconosciuto' : '-')) ?></td>
                            <td><?= htmlspecialchars($user['created_at']) ?></td>
                            <td class="text-end">
                                <div class="d-flex justify-content-end align-items-center gap-2 flex-nowrap">
                                    
                                    <form method="post" class="d-flex gap-2 flex-nowrap" autocomplete="off">
                                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                        <input type="password" name="new_password" class="form-control form-control-sm flex-shrink-0" style="width: 135px;" placeholder="Nuova password" autocomplete="new-password" required>
                                        <input type="password" name="confirm_password" class="form-control form-control-sm flex-shrink-0" style="width: 100px;" placeholder="Conferma" autocomplete="new-password" required>
                                        <button type="submit" name="update_password" class="btn btn-sm btn-outline-primary flex-shrink-0" title="Salva nuova password">
                                            <i class="bi bi-floppy-fill" aria-hidden="true"></i> 
                                            <span class="visually-hidden">Aggiorna password</span>
                                        </button>
                                    </form>

                                    <?php if ($user['id'] !== (int)$_SESSION['user_id']): ?>
                                        <?php 
                                            // Costruzione del messaggio di conferma personalizzato
                                            if ($user['role'] === 'superuser') {
                                                $confirmMessage = 'Attenzione! Stai per cancellare l\'account Superuser. Questa operazione è irreversibile e disabilita l\'intero sistema se non ci sono altri Superuser attivi.';
                                            } elseif ($user['role'] === 'admin' && $currentRole === 'superuser') {
                                                // AVVISO POTENZIATO PER CANCELLAZIONE ADMIN DA SUPERUSER (IRREVERSIBILE)
                                                // NUOVO MESSAGGIO RICHIESTO:
                                                $confirmMessage = 'AZIONE IRREVERSIBILE! Sei sicuro di voler eliminare questo Admin ' . $user['email'] . '? Questa azione eliminerà DEFINITIVAMENTE ' . $user['email'] . ' e tutti i suoi utenti gestiti e TUTTE le loro schede. I dati NON saranno recuperabili dal cestino.';
                                            } elseif ($user['role'] === 'admin') {
                                                // Admin che prova a cancellare un Admin (bloccato via PHP)
                                                $confirmMessage = 'Non hai i permessi per eliminare questo Admin.';
                                            } else {
                                                // Utente Standard eliminato da Admin (Schede riassegnate)
                                                $confirmMessage = 'Sei sicuro di voler eliminare questo utente? Le sue schede verranno riassegnate al tuo account.';
                                            }
                                        ?>
                                        <form method="post" onsubmit="return confirm('<?= addslashes(htmlspecialchars($confirmMessage)) ?>');" class="flex-shrink-0">
                                            <input type="hidden" name="delete_id" value="<?= $user['id'] ?>">
                                            <button type="submit" class="btn btn-sm btn-outline-danger" title="Elimina utente">
                                                <i class="bi bi-trash" aria-hidden="true"></i>
                                                <span class="visually-hidden">Elimina</span>
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
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>