<?php
require_once __DIR__ . '/includes/auth.php';

// --- Funzione getAppSetting (Necessaria se non inclusa in auth.php) ---
if (!function_exists('getAppSetting')) {
    function getAppSetting(PDO $pdo, string $name, string $default = ''): string
    {
        $stmt = $pdo->prepare("SELECT value FROM app_settings WHERE name = ?");
        $stmt->execute([$name]);
        $result = $stmt->fetchColumn();
        return $result !== false ? $result : $default;
    }
}
// ----------------------------------------------------------------------------------

// Controlla se l'utente è già loggato
if (isset($_SESSION['user_id'])) {
    header('Location: home.php'); // Reindirizza alla nuova Home
    exit;
}

$error = null;
$info = null;

// Gestione del messaggio di timeout
if (isset($_GET['timeout'])) {
    $info = 'Sessione terminata per inattività. Accedi nuovamente.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    // Inizializza il processo di login in auth.php
    $result = initiateLogin($pdo, $email, $password);
    
    if ($result) {
        
        // ===============================================
        // CONTROLLO UTENZA SOSPESA
        // ===============================================
        if (isset($result['suspended']) && $result['suspended']) {
            
            // Legge il messaggio personalizzato dal database
            $customMessage = getAppSetting($pdo, 'suspension_message'); 
            
            if (!empty($customMessage)) {
                // Decodifichiamo eventuali entità HTML presenti nel DB
                $error = html_entity_decode($customMessage, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            } else {
                $error = 'Utenza sospesa, si prega di contattare il gestore.';
            }
        }
        // ===============================================
        
        // Se non sospeso, procedi con OTP o login diretto
        elseif (!($result['require_otp'] ?? true)) {
            // Login diretto (Superuser o OTP disabilitato)
            header('Location: home.php'); // Reindirizza alla nuova Home
            exit;
        } else {
            // Reindirizza a verifica OTP
            header('Location: verify_otp.php');
            exit;
        }
    } else {
        $error = 'Credenziali non valide.';
    }
}
?>
<!doctype html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
    <title>Accesso - Vault</title>
</head>
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-5">
            <div class="card shadow-sm mt-5">
                <div class="card-body p-4">
                    
                    <div class="text-center mb-4">
                        <img src="assets/logocards.png" alt="Logo" style="max-width: 150px; height: auto;">
                    </div>

                    <h1 class="h4 mb-3 text-center">Accesso</h1>
                    
                    <?php if ($info): ?>
                        <div class="alert alert-info"><?= htmlspecialchars($info) ?></div>
                    <?php endif; ?>
                    
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>
                    
                    <form method="post">
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" name="email" id="email" required autofocus>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" name="password" id="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Accedi</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>