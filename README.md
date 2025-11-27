# Vault PHP/MySQL demo

Applicazione PHP minimale per la gestione di schede con credenziali multiple e note. Include autenticazione a due fattori (OTP via email), ruoli gerarchici (superuser, admin, utente) e cifratura delle password salvate nelle schede.

## Requisiti
- PHP 8.1+
- MySQL 8+
- Estensione OpenSSL attiva

## Setup
1. Copia `config.php` e aggiorna le credenziali del database e la chiave di cifratura.
2. Crea il database e importa lo schema:
   ```sql
   CREATE DATABASE vault_app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   USE vault_app;
   SOURCE init_db.sql;
   ```
3. Configura il virtual host o esegui un server PHP locale:
   ```bash
   php -S localhost:8000
   ```
4. Accedi con il superuser iniziale `superuser@example.com` / `superuser123`, quindi crea gli admin e gli utenti.

## Funzionalità principali
- Login con email/password e verifica OTP (codice inviato via email e registrato in `otp_log.txt` per test).
- Gestione ruoli: il superuser crea admin, gli admin gestiscono gli utenti standard.
- CRUD delle schede con blocchi dinamici (login/password/url) e note.
- Password delle schede cifrate con AES-256-CBC tramite la chiave definita in `config.php`.
- Pulsante occhio per mostrare/nascondere password e icona link per aprire la URL in nuova scheda.
- Logout disponibile da tutte le pagine protette.

## Sicurezza
- Le password utente sono memorizzate con `password_hash`/`password_verify`.
- Le password delle schede sono cifrate lato server prima di essere salvate.
- Cambia la chiave `encryption_key` in produzione e configura un sistema di invio email reale per l'OTP.
