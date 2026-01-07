<?php
require_once __DIR__ . '/crypto.php';

function createCardBackup(PDO $pdo, int $cardId, int $actorId): bool
{
    $stmt = $pdo->prepare('SELECT * FROM cards WHERE id = ?');
    $stmt->execute([$cardId]);
    $card = $stmt->fetch();
    if (!$card) {
        return false;
    }

    $entriesStmt = $pdo->prepare('SELECT login, password_encrypted, url, note FROM card_entries WHERE card_id = ?');
    $entriesStmt->execute([$cardId]);
    $entries = $entriesStmt->fetchAll();

    try {
        $pdo->beginTransaction();

        $insertBackup = $pdo->prepare('INSERT INTO card_backups (card_id, name, notes, owner_id, admin_id, privacy_level, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)');
        $insertBackup->execute([
            $card['id'],
            $card['name'],
            $card['notes'],
            $card['owner_id'],
            $card['admin_id'],
            $card['privacy_level'],
            $actorId,
        ]);
        $backupId = (int)$pdo->lastInsertId();

        if ($entries) {
            $insertEntry = $pdo->prepare('INSERT INTO card_backup_entries (backup_id, login, password_encrypted, url, note) VALUES (?, ?, ?, ?, ?)');
            foreach ($entries as $entry) {
                $insertEntry->execute([
                    $backupId,
                    $entry['login'],
                    $entry['password_encrypted'],
                    $entry['url'],
                    $entry['note'],
                ]);
            }
        }

        $idListStmt = $pdo->prepare('SELECT id FROM card_backups WHERE card_id = ? ORDER BY created_at DESC, id DESC');
        $idListStmt->execute([$cardId]);
        $ids = $idListStmt->fetchAll(PDO::FETCH_COLUMN);
        if (count($ids) > 10) {
            $idsToDelete = array_slice($ids, 10);
            $placeholders = implode(',', array_fill(0, count($idsToDelete), '?'));
            $deleteStmt = $pdo->prepare("DELETE FROM card_backups WHERE id IN ($placeholders)");
            $deleteStmt->execute($idsToDelete);
        }

        $pdo->commit();
        return true;
    } catch (Throwable $e) {
        $pdo->rollBack();
        return false;
    }
}

function getCardBackups(PDO $pdo, int $cardId): array
{
    $stmt = $pdo->prepare('SELECT b.*, u.email AS created_by_email FROM card_backups b LEFT JOIN users u ON u.id = b.created_by WHERE b.card_id = ? ORDER BY b.created_at DESC, b.id DESC LIMIT 10');
    $stmt->execute([$cardId]);
    return $stmt->fetchAll();
}

function restoreCardBackup(PDO $pdo, int $cardId, int $backupId, int $actorId): bool
{
    $backupStmt = $pdo->prepare('SELECT * FROM card_backups WHERE id = ? AND card_id = ?');
    $backupStmt->execute([$backupId, $cardId]);
    $backup = $backupStmt->fetch();
    if (!$backup) {
        return false;
    }

    $entriesStmt = $pdo->prepare('SELECT login, password_encrypted, url, note FROM card_backup_entries WHERE backup_id = ?');
    $entriesStmt->execute([$backupId]);
    $entries = $entriesStmt->fetchAll();

    try {
        $pdo->beginTransaction();
        $updateCard = $pdo->prepare('UPDATE cards SET name = ?, notes = ?, owner_id = ?, admin_id = ?, privacy_level = ?, updated_at = NOW(), last_modified_by = ? WHERE id = ?');
        $updateCard->execute([
            $backup['name'],
            $backup['notes'],
            $backup['owner_id'],
            $backup['admin_id'],
            $backup['privacy_level'],
            $actorId,
            $cardId,
        ]);

        $pdo->prepare('DELETE FROM card_entries WHERE card_id = ?')->execute([$cardId]);

        if ($entries) {
            $insertEntry = $pdo->prepare('INSERT INTO card_entries (card_id, login, password_encrypted, url, note) VALUES (?, ?, ?, ?, ?)');
            foreach ($entries as $entry) {
                $insertEntry->execute([
                    $cardId,
                    $entry['login'],
                    $entry['password_encrypted'],
                    $entry['url'],
                    $entry['note'],
                ]);
            }
        }

        $pdo->commit();
        return true;
    } catch (Throwable $e) {
        $pdo->rollBack();
        return false;
    }
}