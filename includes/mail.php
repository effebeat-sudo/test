<?php
// Carica l'autoloader di Composer per rendere disponibili le classi PHPMailer
require_once __DIR__ . '/../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

/**
 * Funzione generica per inviare email usando le configurazioni fornite.
 * @param array $settings Array associativo contenente host, port, username, password, encryption, from_email, from_name.
 * @param string $recipient Email del destinatario.
 * @param string $subject Oggetto dell'email.
 * @param string $body Contenuto dell'email (HTML o testo).
 * @return bool True in caso di successo, false altrimenti.
 */
function sendMail(array $settings, string $recipient, string $subject, string $body): bool
{
    $mail = new PHPMailer(true);
    try {
        // --- CONFIGURAZIONE SMTP ---
        $mail->isSMTP();
        $mail->Host       = $settings['host'];
        $mail->SMTPAuth   = true;
        $mail->Username   = $settings['username'];
        $mail->Password   = $settings['password'];
        $mail->Port       = $settings['port'];
        $mail->CharSet    = 'UTF-8';
        $mail->SMTPOptions = [
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            ]
        ];
        
        // Gestione Cifratura
        if ($settings['encryption'] === 'ssl') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // Usa SMTPS per SSL sulla porta 465
        } elseif ($settings['encryption'] === 'tls') {
             $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // Usa STARTTLS
        } else {
            $mail->SMTPSecure = false; // Nessuna cifratura
        }

        // --- DESTINATARI ---
        $mail->setFrom($settings['from_email'], $settings['from_name']);
        $mail->addAddress($recipient);

        // --- CONTENUTO ---
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $body;
        $mail->AltBody = strip_tags($body); // Versione in testo semplice

        $mail->send();
        return true;
        
    } catch (Exception $e) {
        // Log dell'errore completo per il debug
        error_log("Invio fallito a {$recipient}. Errore PHPMailer: " . $mail->ErrorInfo);
        return false;
    }
}

// =================================================================================
// FUNZIONI WRAPPER UTILIZZATE DAL RESTO DEL SISTEMA (auth.php, superuser_panel.php)
// =================================================================================


/**
 * Invia un'email di prova utilizzando le impostazioni SMTP fornite.
 * Chiamata da superuser_panel.php.
 */
function sendTestEmail(array $settings, string $recipient, string $subject, string $body): bool
{
    return sendMail($settings, $recipient, $subject, $body);
}


/**
 * Invia l'OTP all'utente.
 * Chiamata da auth.php. Deve recuperare i settings dal DB tramite $pdo.
 */
function sendOtpEmail(PDO $pdo, string $recipient, string $otp): bool
{
    // Funzione placeholder: Qui devi implementare il recupero delle impostazioni SMTP persistenti
    // che sono state salvate nel DB tramite il Superuser Panel.
    
    // Assumendo che esista una funzione loadMailSettings o simile accessibile
    // dal contesto globale/auth.php
    
    // Placeholder: Recupera le impostazioni (la password sarà già decriptata)
    $settings = loadMailSettings($pdo, /* defaults da config.php */);
    
    if (!$settings || empty($settings['host'])) {
        error_log("Impossibile inviare OTP: Impostazioni SMTP non disponibili nel DB.");
        return false;
    }

    $subject = "Codice di Accesso Unico (OTP)";
    $body = "Il tuo codice di accesso OTP è: <strong>{$otp}</strong>. Questo codice scadrà in 5 minuti. Non condividerlo.";
    
    return sendMail($settings, $recipient, $subject, $body);
}

// === FUNZIONE PLACEHOLDER PER RECUPERO IMPOSTAZIONI DAL DB ===
// Questa DEVE essere implementata nel tuo includes/auth.php o in un file di utilità.
if (!function_exists('loadMailSettings')) {
    function loadMailSettings(PDO $pdo, array $defaultSettings): array {
        // ATTENZIONE: Questo è solo un placeholder che restituisce i valori di default.
        // Devi implementare la logica per recuperare i valori da app_settings (compresa la decriptazione della password)
        // usando le funzioni getAppSetting() e decryptValue().
        error_log("ATTENZIONE: loadMailSettings non implementata o non accessibile.");
        return $defaultSettings;
    }
}