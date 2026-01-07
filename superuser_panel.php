<?php
// superuser_panel.php - Gestione configurazioni di sistema e operazioni Superuser

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/mail.php'; 

requireRole('superuser'); 

// ==================================================================================
// FUNZIONI DI UTILITÀ E PERSISTENZA (Definite localmente per garantire autonomia)
// ==================================================================================

if (!function_exists('getAppSetting')) {
    function getAppSetting(PDO $pdo, string $name, string $default = ''): string
    {
        $stmt = $pdo->prepare("SELECT value FROM app_settings WHERE name = ?");
        $stmt->execute([$name]);
        $result = $stmt->fetchColumn();
        return $result !== false ? $result : $default;
    }
}

if (!function_exists('setAppSetting')) {
    function setAppSetting(PDO $pdo, string $name, string $value): bool
    {
        try {
            $stmt = $pdo->prepare("
                INSERT INTO app_settings (name, value) VALUES (?, ?)
                ON DUPLICATE KEY UPDATE value = VALUES(value)
            ");
            return $stmt->execute([$name, $value]);
        } catch (\PDOException $e) {
            error_log("DB Error in setAppSetting: " . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('loadMailSettings')) {
    function loadMailSettings(PDO $pdo, array $defaultSettings): array
    {
        $settings = [];
        foreach (array_keys($defaultSettings) as $key) {
            $value = getAppSetting($pdo, 'mail_' . $key, $defaultSettings[$key]);
            if ($key === 'password') {
                $settings[$key] = decryptValue($value);
            } else {
                $settings[$key] = $value;
            }
        }
        return $settings;
    }
}

if (!function_exists('saveMailSettings')) {
    function saveMailSettings(PDO $pdo, array $settings): bool
    {
        try {
            foreach ($settings as $key => $value) {
                $settingName = 'mail_' . $key;
                $valueToSave = $value;
                if ($key === 'password') {
                    $valueToSave = encryptValue($value); 
                }
                if (!setAppSetting($pdo, $settingName, $valueToSave)) {
                    return false;
                }
            }
            return true;
        } catch (Throwable $e) {
            error_log("DB Error during saveMailSettings: " . $e->getMessage());
            return false;
        }
    }
}

// Funzione RINOMINATA per evitare conflitti con versioni precedenti in auth.php
if (!function_exists('performBulkDelete')) {
    function performBulkDelete(PDO $pdo, int $adminId): bool
    {
        // 1. Verifica che l'ID appartenga a un Admin
        $adminStmt = $pdo->prepare("SELECT id FROM users WHERE id = ? AND role = 'admin' LIMIT 1");
        $adminStmt->execute([$adminId]);
        if (!$adminStmt->fetch()) {
            return false;
        }
        
        $currentUserId = (int)($_SESSION['user_id'] ?? 0); 
        if ($currentUserId === 0) return false; 

        try {
            $pdo->beginTransaction();

            // 2. Trova tutti gli utenti creati da questo admin
            $userStmt = $pdo->prepare('SELECT id FROM users WHERE created_by = ?');
            $userStmt->execute([$adminId]);
            // Usa FETCH_COLUMN per ottenere un array pulito di ID
            $managedUserIds = $userStmt->fetchAll(PDO::FETCH_COLUMN);
            
            // 3. Unisci Admin + Suoi Utenti
            $ownerIds = array_merge([$adminId], $managedUserIds);
            
            if (empty($ownerIds)) {
                $pdo->rollBack();
                return false;
            }

            $placeholders = implode(',', array_fill(0, count($ownerIds), '?'));
            
            // 4. Esegui l'aggiornamento
            $sql = "UPDATE cards 
                    SET deleted_at = NOW(), 
                        deleted_by = ?, 
                        restored_at = NULL, 
                        restored_by = NULL, 
                        last_modified_by = ?, 
                        updated_at = NOW() 
                    WHERE deleted_at IS NULL 
                      AND (owner_id IN ($placeholders) OR admin_id = ?)";
            
            // Parametri: [superuser, superuser, ...id_proprietari..., id_admin]
            $params = array_merge([$currentUserId, $currentUserId], $ownerIds, [$adminId]);
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);

            $pdo->commit();
            return true;

        } catch (Exception $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log("Errore DB in performBulkDelete: " . $e->getMessage());
            return false;
        }
    }
}

// ==================================================================================
// LOGICA PAGINA
// ==================================================================================

global $pdo; 

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$impersonating = isImpersonating();
$impersonatorEmail = $_SESSION['impersonator_email'] ?? null;

$message = null;
$messageClass = 'success';
$currentTimeoutMinutes = getSessionTimeoutMinutes($pdo); 
$currentOtpEnabled = isOtpEnabled($pdo); 

// Configurazione Mail
$config = require __DIR__ . '/config.php'; 
$defaultMailSettings = $config['mail'];
$mailSettings = loadMailSettings($pdo, $defaultMailSettings);

$currentMailHost = $mailSettings['host'] ?? '';
$currentMailPort = $mailSettings['port'] ?? 465;
$currentMailEncryption = $mailSettings['encryption'] ?? 'ssl';
$currentMailUsername = $mailSettings['username'] ?? '';
$currentMailPassword = $mailSettings['password'] ?? ''; 
$currentMailFromEmail = $mailSettings['from_email'] ?? '';
$currentMailFromName = $mailSettings['from_name'] ?? '';

// Configurazione Messaggio Sospensione
$currentSuspensionMessage = getAppSetting($pdo, 'suspension_message', 'Utenza sospesa, si prega di contattare il gestore.');

// Popolamento Liste Admin/Utenti
$admins = $pdo->query("SELECT id, email FROM users WHERE role = 'admin' ORDER BY email")->fetchAll(PDO::FETCH_ASSOC);
$adminIds = $admins ? array_column($admins, 'id') : [];
$usersByAdmin = [];
$impersonationOptions = [];

if ($adminIds) {
    $placeholders = implode(',', array_fill(0, count($adminIds), '?'));
    $stmt = $pdo->prepare("SELECT id, email, created_by, is_suspended FROM users WHERE role = 'user' AND created_by IN ($placeholders) ORDER BY email");
    $stmt->execute($adminIds);
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $usersByAdmin[$row['created_by']][] = $row;
    }
}

foreach ($admins as $adminRow) {
    if ((int)$adminRow['id'] === $currentUserId) continue;
    
    $impersonationOptions[htmlspecialchars($adminRow['email']) . ' (Admin)'] = [
        'id' => $adminRow['id'],
        'role' => 'admin',
        'sub_users' => $usersByAdmin[$adminRow['id']] ?? []
    ];
}

// === GESTIONE RICHIESTE POST ===
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 1. MESSAGGIO SOSPENSIONE
    if (isset($_POST['update_suspension_message'])) {
        $newMessage = trim($_POST['suspension_message'] ?? '');
        if (setAppSetting($pdo, 'suspension_message', $newMessage)) {
            $currentSuspensionMessage = $newMessage;
            $message = 'Messaggio di sospensione aggiornato con successo.';
        } else {
            $message = 'Errore nel salvataggio del messaggio.';
            $messageClass = 'danger';
        }
    }

    // 2. SOSPENSIONE UTENTI (Cascata)
    elseif (isset($_POST['toggle_suspension'])) {
        $targetId = (int)$_POST['target_id'];
        $newStatus = (int)($_POST['status'] ?? 0); 
        
        $stmtUser = $pdo->prepare("SELECT id, email, role FROM users WHERE id = ?");
        $stmtUser->execute([$targetId]);
        $targetUser = $stmtUser->fetch(PDO::FETCH_ASSOC);

        if (!$targetUser) {
            $message = 'Utente non trovato.';
            $messageClass = 'danger';
        } elseif ($targetUser['role'] === 'superuser' || $targetId === $currentUserId) {
            $message = 'Impossibile sospendere Superuser o se stessi.';
            $messageClass = 'danger';
        } else {
            $statusText = $newStatus === 1 ? 'sospesa' : 'riattivata';
            try {
                $targetIds = [$targetId];
                // Se è admin, sospendi anche i suoi utenti
                if ($targetUser['role'] === 'admin') {
                    $stmtM = $pdo->prepare("SELECT id FROM users WHERE created_by = ? AND role = 'user'");
                    $stmtM->execute([$targetId]);
                    $managedIds = $stmtM->fetchAll(PDO::FETCH_COLUMN);
                    $targetIds = array_merge($targetIds, $managedIds);
                    $msgDetail = "Admin e " . count($managedIds) . " utenti gestiti";
                } else {
                    $msgDetail = "Utenza " . $targetUser['email'];
                }

                $placeholders = implode(',', array_fill(0, count($targetIds), '?'));
                $stmtUpd = $pdo->prepare("UPDATE users SET is_suspended = ? WHERE id IN ($placeholders)");
                $params = array_merge([$newStatus], $targetIds);
                
                if ($stmtUpd->execute($params)) {
                    // Refresh pagina per vedere aggiornamenti
                    header('Location: superuser_panel.php?message=' . urlencode("$msgDetail $statusText con successo.") . '&class=success');
                    exit;
                } else {
                    $message = "Errore DB durante l'aggiornamento.";
                    $messageClass = 'danger';
                }
            } catch (Exception $e) {
                $message = "Errore: " . $e->getMessage();
                $messageClass = 'danger';
            }
        }
    }
    
    // 3. IMPOSTAZIONI SMTP
    elseif (isset($_POST['update_smtp'])) {
        $newSettings = [
            'host' => trim($_POST['mail_host'] ?? ''),
            'port' => (int)($_POST['mail_port'] ?? 0),
            'encryption' => trim($_POST['mail_encryption'] ?? ''),
            'username' => trim($_POST['mail_username'] ?? ''),
            'password' => $_POST['mail_password'] ?? '',
            'from_email' => trim($_POST['mail_from_email'] ?? ''),
            'from_name' => trim($_POST['mail_from_name'] ?? '')
        ];
        
        if (saveMailSettings($pdo, $newSettings)) {
            $mailSettings = loadMailSettings($pdo, $defaultMailSettings); 
            // Aggiorna variabili locali per il form
            $currentMailHost = $newSettings['host'];
            $currentMailPort = $newSettings['port'];
            $currentMailEncryption = $newSettings['encryption'];
            $currentMailUsername = $newSettings['username'];
            $currentMailPassword = $newSettings['password'];
            $currentMailFromEmail = $newSettings['from_email'];
            $currentMailFromName = $newSettings['from_name'];
            $message = 'Impostazioni SMTP salvate.';
        } else {
            $message = 'Errore salvataggio SMTP.';
            $messageClass = 'danger';
        }
    }

    // 4. TEST EMAIL
    elseif (isset($_POST['test_mail'])) {
        $recipient = trim($_POST['test_recipient'] ?? '');
        if (filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
            $testSettings = [
                'host' => trim($_POST['mail_host']),
                'port' => (int)($_POST['mail_port']),
                'encryption' => trim($_POST['mail_encryption']),
                'username' => trim($_POST['mail_username']),
                'password' => $_POST['mail_password'], 
                'from_email' => trim($_POST['mail_from_email']),
                'from_name' => trim($_POST['mail_from_name']),
            ];
            
            if (sendTestEmail($testSettings, $recipient, "Test SMTP Vault", "Invio riuscito.")) {
                $message = "Email di prova inviata a $recipient.";
            } else {
                $message = "Errore invio email. Controlla log/credenziali.";
                $messageClass = 'danger';
            }
        } else {
            $message = 'Email destinatario non valida.';
            $messageClass = 'danger';
        }
    }
    
    // 5. IMPERSONIFICAZIONE
    elseif (isset($_POST['impersonate_id'])) {
        if (impersonateUser($pdo, (int)$_POST['impersonate_id'])) {
            header('Location: cards.php'); exit;
        }
        $message = 'Impossibile impersonare.'; $messageClass = 'danger';
    } elseif (isset($_POST['stop_impersonation'])) {
        if (stopImpersonation($pdo)) {
            header('Location: superuser_panel.php'); exit;
        }
        $message = 'Errore stop impersonazione.'; $messageClass = 'danger';
    }

    // 6. TIMEOUT & OTP
    elseif (isset($_POST['update_timeout'])) {
        $min = max(5, (int)$_POST['session_timeout']);
        if (setAppSetting($pdo, 'session_timeout_minutes', (string)$min)) {
            $currentTimeoutMinutes = $min;
            $message = "Timeout aggiornato a $min min.";
        } else {
            $message = 'Errore salvataggio timeout.';
            $messageClass = 'danger';
        }
    } elseif (isset($_POST['toggle_otp'])) {
        $st = !empty($_POST['otp_enabled']);
        if (setAppSetting($pdo, 'otp_enabled', $st ? '1' : '0')) {
            $currentOtpEnabled = $st;
            $message = 'Stato OTP aggiornato.';
        } else {
            $message = 'Errore salvataggio OTP.';
            $messageClass = 'danger';
        }
    }

    // 7. CANCELLAZIONE MASSIVA (Fix applicato qui)
    elseif (isset($_POST['bulk_delete_admin'])) {
        $admId = (int)$_POST['admin_id'];
        if ($admId > 0 && performBulkDelete($pdo, $admId)) {
            $message = 'Schede admin e utenti spostate nel cestino.';
        } else {
            $message = 'Errore o admin non valido per cancellazione massiva.';
            $messageClass = 'danger';
        }
    }
}

// Ricarica lista utenti per tabella
$stmtAdmins = $pdo->query("SELECT id, email, role, is_suspended, created_by FROM users ORDER BY role DESC, email ASC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <link href="assets/style.css" rel="stylesheet">
    <title>Pannello Superuser</title>
    <style>.suspension-switch-container{width:100px;}</style>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container py-4">
    <h1 class="h3 mb-4">Pannello di Controllo Superuser</h1>

    <?php if ($impersonating): ?>
        <div class="alert alert-warning mb-4 d-flex justify-content-between align-items-center">
            Stai impersonando: <strong><?= htmlspecialchars($_SESSION['email']) ?></strong>
            <form method="post" class="m-0"><input type="hidden" name="stop_impersonation" value="1"><button class="btn btn-sm btn-warning">Termina</button></form>
        </div>
    <?php endif; ?>

    <?php 
    // Gestione messaggi via GET (da redirect) o variabili locali
    $dispMsg = $message ?? ($_GET['message'] ?? null);
    $dispClass = $messageClass ?? ($_GET['class'] ?? 'success');
    if ($dispMsg): 
    ?>
        <div class="alert alert-<?= htmlspecialchars($dispClass) ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($dispMsg) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <h2 class="h6 mb-3">Gestione Sospensione Utenze</h2>
            <div class="table-responsive">
                <table class="table table-striped align-middle">
                    <thead><tr><th>Email</th><th>Ruolo</th><th class="text-center">Stato</th><th class="text-end">Azione</th></tr></thead>
                    <tbody>
                    <?php foreach ($stmtAdmins as $u): 
                        if ($u['role'] === 'superuser') continue; 
                        $isSusp = (int)$u['is_suspended'] === 1;
                    ?>
                        <tr>
                            <td><?= htmlspecialchars($u['email']) ?></td>
                            <td><span class="badge <?= $u['role']==='admin'?'bg-warning text-dark':'bg-info' ?>"><?= ucfirst($u['role']) ?></span></td>
                            <td class="text-center"><span class="badge <?= $isSusp?'bg-danger':'bg-success' ?>"><?= $isSusp?'Sospesa':'Attiva' ?></span></td>
                            <td class="text-end">
                                <form method="post" class="d-inline">
                                    <input type="hidden" name="toggle_suspension" value="1">
                                    <input type="hidden" name="target_id" value="<?= $u['id'] ?>">
                                    <input type="hidden" name="status" value="<?= $isSusp ? 0 : 1 ?>">
                                    <button class="btn btn-sm <?= $isSusp?'btn-success':'btn-danger' ?>" onclick="return confirm('<?= $isSusp?'Riattivare':'Sospendere' ?> <?= $u['email'] ?>?');">
                                        <?= $isSusp?'Riattiva':'Sospendi' ?>
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <h2 class="h6 mb-3">Configurazione SMTP</h2>
            <form method="post" class="row g-3">
                <input type="hidden" name="update_smtp" value="1">
                <div class="col-md-6"><label class="form-label">Host</label><input type="text" name="mail_host" class="form-control" value="<?= htmlspecialchars($currentMailHost) ?>" required></div>
                <div class="col-md-3"><label class="form-label">Porta</label><input type="number" name="mail_port" class="form-control" value="<?= htmlspecialchars($currentMailPort) ?>" required></div>
                <div class="col-md-3"><label class="form-label">Cifratura</label>
                    <select name="mail_encryption" class="form-select">
                        <option value="ssl" <?= $currentMailEncryption==='ssl'?'selected':'' ?>>SSL</option>
                        <option value="tls" <?= $currentMailEncryption==='tls'?'selected':'' ?>>TLS</option>
                        <option value="" <?= $currentMailEncryption===''?'selected':'' ?>>Nessuna</option>
                    </select>
                </div>
                <div class="col-md-6"><label class="form-label">Username</label><input type="text" name="mail_username" class="form-control" value="<?= htmlspecialchars($currentMailUsername) ?>" required></div>
                <div class="col-md-6"><label class="form-label">Password</label><input type="password" name="mail_password" class="form-control" value="<?= htmlspecialchars($currentMailPassword) ?>"></div>
                <div class="col-md-6"><label class="form-label">Da (Email)</label><input type="email" name="mail_from_email" class="form-control" value="<?= htmlspecialchars($currentMailFromEmail) ?>" required></div>
                <div class="col-md-6"><label class="form-label">Da (Nome)</label><input type="text" name="mail_from_name" class="form-control" value="<?= htmlspecialchars($currentMailFromName) ?>" required></div>
                <div class="col-12"><button class="btn btn-success w-100"><i class="bi bi-floppy-fill"></i> Salva SMTP</button></div>
            </form>
            
            <hr class="my-4">
            <h3 class="h6 mb-3">Test Email</h3>
            <form method="post" class="row g-2">
                <input type="hidden" name="test_mail" value="1">
                <input type="hidden" name="mail_host" value="<?= htmlspecialchars($currentMailHost) ?>">
                <input type="hidden" name="mail_port" value="<?= htmlspecialchars($currentMailPort) ?>">
                <input type="hidden" name="mail_encryption" value="<?= htmlspecialchars($currentMailEncryption) ?>">
                <input type="hidden" name="mail_username" value="<?= htmlspecialchars($currentMailUsername) ?>">
                <input type="hidden" name="mail_password" value="<?= htmlspecialchars($currentMailPassword) ?>">
                <input type="hidden" name="mail_from_email" value="<?= htmlspecialchars($currentMailFromEmail) ?>">
                <input type="hidden" name="mail_from_name" value="<?= htmlspecialchars($currentMailFromName) ?>">
                
                <div class="col-md-9"><input type="email" name="test_recipient" class="form-control" value="<?= htmlspecialchars($currentUser['email']) ?>" required></div>
                <div class="col-md-3"><button class="btn btn-outline-info w-100">Invia Test</button></div>
            </form>
        </div>
    </div>

    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <h2 class="h6 mb-3">Impersonificazione</h2>
            <form method="post" class="row g-2">
                <div class="col-md-9">
                    <select name="impersonate_id" class="form-select" required>
                        <option value="">Seleziona utente...</option>
                        <?php foreach ($impersonationOptions as $lbl => $data): ?>
                            <option value="<?= $data['id'] ?>"><?= htmlspecialchars($lbl) ?></option>
                            <?php foreach ($data['sub_users'] as $su): ?>
                                <option value="<?= $su['id'] ?>" <?= ((int)$su['is_suspended']===1)?'disabled':'' ?>> &nbsp; - <?= htmlspecialchars($su['email']) ?> <?= ((int)$su['is_suspended']===1)?'(SOSPESO)':'' ?></option>
                            <?php endforeach; ?>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3"><button class="btn btn-primary w-100">Accedi come</button></div>
            </form>
        </div>
    </div>

    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <h2 class="h6 mb-3">Sicurezza Globale</h2>
            <form method="post" class="row g-2 mb-3">
                <input type="hidden" name="update_timeout" value="1">
                <div class="col-md-9">
                    <label class="form-label">Timeout Sessione (min)</label>
                    <input type="number" name="session_timeout" class="form-control" value="<?= $currentTimeoutMinutes ?>" min="5" required>
                </div>
                <div class="col-md-3 d-flex align-items-end"><button class="btn btn-primary w-100">Salva</button></div>
            </form>

            <form method="post" class="mb-3">
                <input type="hidden" name="toggle_otp" value="1">
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="otp_switch" name="otp_enabled" value="1" <?= $currentOtpEnabled?'checked':'' ?> onchange="this.form.submit()">
                    <label class="form-check-label" for="otp_switch">Abilita OTP per tutti (escluso Superuser)</label>
                </div>
            </form>
            
            <hr>
            
            <h2 class="h6 mb-3">Messaggio Utenza Sospesa</h2>
            <form method="post" class="row g-2">
                <input type="hidden" name="update_suspension_message" value="1">
                <div class="col-md-9">
                    <textarea name="suspension_message" class="form-control" rows="2"><?= htmlspecialchars($currentSuspensionMessage) ?></textarea>
                </div>
                <div class="col-md-3"><button class="btn btn-primary w-100">Salva Msg</button></div>
            </form>
        </div>
    </div>

    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <h2 class="h6 mb-3">Cancellazione Massiva (Sposta nel Cestino)</h2>
            <form method="post" class="row g-2" onsubmit="return confirm('Spostare nel cestino TUTTE le schede di questo Admin e dei suoi utenti?');">
                <input type="hidden" name="bulk_delete_admin" value="1">
                <div class="col-md-9">
                    <select name="admin_id" class="form-select" required>
                        <option value="">Seleziona Admin...</option>
                        <?php foreach ($admins as $adm): ?>
                            <option value="<?= $adm['id'] ?>"><?= htmlspecialchars($adm['email']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3"><button class="btn btn-danger w-100">Sposta nel Cestino</button></div>
            </form>
        </div>
    </div>

</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>