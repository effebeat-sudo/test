<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
requireLogin();

$currentUser = currentUser($pdo);
$currentUserId = (int)($_SESSION['user_id'] ?? 0);
$currentRole = $_SESSION['role'] ?? 'user';
$userAdminId = $currentUser['created_by'] ?? null;

if (!in_array($currentRole, ['admin', 'superuser'], true)) {
    http_response_code(403);
    echo 'Accesso negato';
    exit;
}

$message = null;
$messageClass = 'success';

// Nuove intestazioni CSV definite dall'utente (9 campi)
$csvHeaders = [
    'card_id', 
    'card_name', 
    'entry_notes', // Mappato a ce.note
    'privacy_level', 
    'owner_email', 
    'entry_login', 
    'entry_password', // Decifrato
    'entry_url', 
    'card_notes' // Mappato a c.notes
];

function buildScopeWhere(PDO $pdo, string $role, int $userId, ?int $userAdminId): array
{
    $where = [];
    $params = [];

    if ($role === 'superuser') {
        $where[] = 'c.owner_id = :owner_id';
        $params['owner_id'] = $userId;
    } elseif ($role === 'admin') {
        $where[] = '(c.admin_id = :admin_id OR c.owner_id = :owner_owner_id OR o.created_by = :creator_id)';
        $params['admin_id'] = $userId;
        $params['owner_owner_id'] = $userId;
        $params['creator_id'] = $userId;
    }

    $where[] = 'c.deleted_at IS NULL';

    return [$where, $params];
}

function getOwnerIdFromEmail(PDO $pdo, string $email, string $currentRole, int $currentUserId): ?int
{
    $stmt = $pdo->prepare('SELECT id, role, created_by FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $owner = $stmt->fetch();

    if (!$owner) {
        return null;
    }

    $ownerId = (int)$owner['id'];
    $ownerRole = $owner['role'];
    $ownerCreatorId = (int)($owner['created_by'] ?? 0);

    if ($currentRole === 'superuser') {
        return $ownerId;
    }

    if ($currentRole === 'admin') {
        if ($ownerId === $currentUserId) { 
            return $ownerId;
        }
        if ($ownerRole === 'user' && $ownerCreatorId === $currentUserId) {
            return $ownerId;
        }
        return null; 
    }

    return null;
}

if (isset($_GET['export'])) {
    [$where, $params] = buildScopeWhere($pdo, $currentRole, $currentUserId, $userAdminId);

    $whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';
    
    // QUERY AGGIORNATA per l'esportazione
    $sql = "
        SELECT 
            c.id AS card_id, 
            c.name AS card_name, 
            c.notes AS card_notes, 
            c.privacy_level,
            o.email AS owner_email,
            ce.login AS entry_login, 
            ce.password_encrypted AS entry_password_encrypted, 
            ce.url AS entry_url,
            ce.note AS entry_note,
            ce.id AS entry_index_for_ordering 
        FROM cards c
        JOIN users o ON o.id = c.owner_id
        LEFT JOIN card_entries ce ON ce.card_id = c.id
        $whereSql
        ORDER BY c.id, ce.id
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $results = $stmt->fetchAll();

    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="cards_export_' . date('Ymd_His') . '.csv"');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Expires: 0');
    
    $output = fopen('php://output', 'w');

    // Headers AGGIORNATI
    fputcsv($output, $csvHeaders);

    // Data Mapping AGGIORNATA
    foreach ($results as $row) {
        $decryptedPassword = '';
        if ($row['entry_password_encrypted']) {
            $decryptedPassword = decryptValue($row['entry_password_encrypted']);
        }

        fputcsv($output, [
            $row['card_id'],
            $row['card_name'],
            $row['entry_note'], 
            $row['privacy_level'],
            $row['owner_email'],
            $row['entry_login'],
            $decryptedPassword, 
            $row['entry_url'],
            $row['card_notes'], 
        ]);
    }

    fclose($output);
    exit;
}

if (isset($_POST['import_csv'])) {
    if (empty($_FILES['csv_file']['tmp_name'])) {
        $message = 'Nessun file caricato.';
        $messageClass = 'danger';
    } else {
        $file = $_FILES['csv_file']['tmp_name'];
        $handle = fopen($file, 'r');
        $headers = fgetcsv($handle);
        
        // Verifica l'esattezza delle intestazioni
        if ($headers !== $csvHeaders) {
            $message = 'Intestazioni del file CSV non valide o in ordine errato. Assicurati che siano esattamente: ' . implode(', ', $csvHeaders);
            $messageClass = 'danger';
            
        } else {
            // Usa le intestazioni esatte per la mappatura
            $headerMap = array_flip($csvHeaders);
            
            $importData = [];
            $importedCardsCount = 0;
            $ignoredRowsCount = 0;

            try {
                // Lettura e raggruppamento dei dati
                while (($row = fgetcsv($handle)) !== false) {
                    if (count($row) !== 9) { // Verifica numero di colonne
                        $ignoredRowsCount++;
                        continue;
                    }

                    // Mappatura temporanea per facilità di accesso
                    $tempRow = array_combine($csvHeaders, $row);

                    $cardId = $tempRow['card_id']; // ID raggruppamento (non da inserire)
                    $ownerEmail = trim($tempRow['owner_email']);

                    // Controlla l'autorizzazione per l'owner_email
                    $ownerId = getOwnerIdFromEmail($pdo, $ownerEmail, $currentRole, $currentUserId);
                    
                    if (!$ownerId) {
                        $ignoredRowsCount++;
                        continue;
                    }

                    // Determina l'admin_id
                    $adminId = null;
                    // Logica di assegnazione Admin ID
                    $stmt = $pdo->prepare('SELECT role, created_by FROM users WHERE id = ?');
                    $stmt->execute([$ownerId]);
                    $ownerUser = $stmt->fetch();
                    if ($ownerUser) {
                        if ($ownerUser['role'] === 'admin') {
                            $adminId = $ownerId;
                        } elseif ($ownerUser['role'] === 'user') {
                            $adminId = (int)$ownerUser['created_by'];
                        }
                    }
                    
                    // Usa il vecchio cardId come chiave di raggruppamento temporanea
                    if (!isset($importData[$cardId])) {
                        $importData[$cardId] = [
                            'card_name' => $tempRow['card_name'],
                            'card_notes' => $tempRow['card_notes'], // Mappato a card_notes
                            'privacy_level' => $tempRow['privacy_level'],
                            'owner_id' => $ownerId,
                            'admin_id' => $adminId,
                            'entries' => [],
                        ];
                    }

                    // Aggiungi l'entry alla scheda
                    $importData[$cardId]['entries'][] = [
                        'entry_login' => $tempRow['entry_login'],
                        'entry_password' => $tempRow['entry_password'], // Password non cifrata
                        'entry_url' => $tempRow['entry_url'],
                        'entry_note' => $tempRow['entry_notes'], // Mappato a entry_notes
                    ];
                }

                if (empty($importData)) {
                    $message = 'Nessun dato valido da importare.';
                    $messageClass = 'warning';
                } else {
                    $pdo->beginTransaction();

                    foreach ($importData as $oldCardId => $cardData) {
                        $newCardId = null;

                        // 1. Inserisci la scheda (COME NUOVA)
                        // Non includiamo l'ID, usiamo i valori di default per created/updated_at e lasciamo AUTO_INCREMENT generare il nuovo ID
                        $stmt = $pdo->prepare('INSERT INTO cards (name, notes, owner_id, admin_id, privacy_level, created_at, updated_at, last_modified_by) VALUES (?, ?, ?, ?, ?, NOW(), NOW(), ?)');
                        $stmt->execute([
                            $cardData['card_name'], 
                            $cardData['card_notes'], 
                            $cardData['owner_id'], 
                            $cardData['admin_id'], 
                            $cardData['privacy_level'], 
                            $currentUserId 
                        ]);
                        $newCardId = (int)$pdo->lastInsertId();
                        $importedCardsCount++;

                        // 2. Inserisci le entry (COME NUOVE)
                        // Non includiamo l'ID, usiamo AUTO_INCREMENT per generare il nuovo ID di card_entries
                        $stmtEntry = $pdo->prepare('INSERT INTO card_entries (card_id, login, password_encrypted, url, note) VALUES (?, ?, ?, ?, ?)');
                        foreach ($cardData['entries'] as $entry) {
                            $encryptedPassword = encryptValue($entry['entry_password']);
                            
                            $stmtEntry->execute([
                                $newCardId, // Usa il nuovo ID della scheda
                                $entry['entry_login'],
                                $encryptedPassword,
                                $entry['entry_url'],
                                $entry['entry_note'],
                            ]);
                        }
                    }

                    $pdo->commit();
                    $message = "Importazione completata. Schede importate: $importedCardsCount. Righe ignorate: $ignoredRowsCount.";
                    $messageClass = 'success';
                }

            } catch (Exception $e) {
                $pdo->rollBack();
                $message = 'Errore durante l\'importazione: ' . $e->getMessage();
                $messageClass = 'danger';
            } finally {
                if (isset($handle)) {
                    fclose($handle);
                }
            }
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
    <title>Trasferimento dati</title>
</head>
<body>

<?php require_once __DIR__ . '/menu.php'; ?>

<div class="container">
    <h1 class="h4 mb-4">Trasferimento dati (Import/Export)</h1>

    <?php if ($message): ?>
        <div class="alert alert-<?= htmlspecialchars($messageClass) ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div class="row g-4">
        <div class="col-lg-6">
            <div class="card shadow-sm h-100">
                <div class="card-body">
                    <h2 class="h5">Esporta dati</h2>
                    <p class="text-muted">Esporta le schede che puoi gestire in un file CSV. Le password vengono decifrate nel CSV.</p>
                    <a class="btn btn-primary" href="data_transfer.php?export=1"><i class="bi bi-download"></i> Scarica CSV</a>
                </div>
            </div>
        </div>
        <div class="col-lg-6">
            <div class="card shadow-sm h-100">
                <div class="card-body">
                    <h2 class="h5">Importa dati</h2>
                    <p class="text-muted">Carica un CSV con le colonne: <code>card_id</code>, <code>card_name</code>, <code>entry_notes</code>, <code>privacy_level</code>, <code>owner_email</code>, <code>entry_login</code>, <code>entry_password</code>, <code>entry_url</code>, <code>card_notes</code>.</p>
                    <form method="post" enctype="multipart/form-data">
                        <div class="mb-3">
                            <label for="csv_file" class="form-label">File CSV</label>
                            <input class="form-control" type="file" id="csv_file" name="csv_file" accept=".csv" required>
                        </div>
                        <input type="hidden" name="import_csv" value="1">
                        <button type="submit" class="btn btn-success"><i class="bi bi-upload"></i> Importa</button>
                    </form>
                    <p class="small text-muted mt-3">Le schede importate vengono raggruppate per <code>card_id</code> (usato solo come indice di raggruppamento) e assegnate all'owner indicato solo se appartiene a te o agli utenti sotto la tua gestione. L'importazione crea sempre **nuovi ID** per schede e blocchi.</p>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>