<?php
require_once __DIR__ . '/includes/auth.php';

if (!isset($_SESSION['pending_user_id'])) {
    header('Location: login.php');
    exit;
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $otp = trim($_POST['otp'] ?? '');
    $userId = (int)$_SESSION['pending_user_id'];
    if (verifyOtp($pdo, $userId, $otp)) {
        header('Location: cards.php');
        exit;
    } else {
        $error = 'OTP non valido o scaduto.';
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
    <title>Verifica OTP</title>
</head>
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-5">
            <div class="card shadow-sm">
                <div class="card-body">
                    <h1 class="h5 mb-3">Inserisci il codice ricevuto via email</h1>
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php else: ?>
                        <div class="alert alert-info">Controlla la tua email per l'OTP.</div>
                    <?php endif; ?>
                    <form method="post">
                        <div class="mb-3">
                            <label for="otp" class="form-label">Codice OTP</label>
                            <input type="text" class="form-control" name="otp" id="otp" required pattern="\d{6}" maxlength="6">
                        </div>
                        <button type="submit" class="btn btn-success w-100">Accedi</button>
                    </form>
                    <a href="login.php" class="d-block text-center mt-3">Torna al login</a>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
