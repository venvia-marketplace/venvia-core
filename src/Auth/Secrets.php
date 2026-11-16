<?php
declare(strict_types=1);
namespace VenVia\Auth;

final class Secrets
{
    public static function passwordHash(#[\SensitiveParameter] string $password): string
    {
        if (strlen($password) > 1024 || !mb_check_encoding($password, 'UTF-8') || mb_strlen($password, 'UTF-8') < 15 || str_contains($password, "\0")) {
            throw new \InvalidArgumentException('Password non conforme');
        }
        if (!defined('PASSWORD_ARGON2ID')) {
            throw new \RuntimeException('Argon2id non disponibile');
        }
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    public static function verifyPassword(#[\SensitiveParameter] string $password, string $hash): bool
    {
        return strlen($password) <= 1024 && !str_contains($password, "\0") && password_verify($password, $hash);
    }

    public static function newRecoveryKey(): string
    {
        return bin2hex(random_bytes(32));
    }

    public static function recoveryDigest(#[\SensitiveParameter] string $key): string
    {
        if (!preg_match('/\A[0-9a-f]{64}\z/D', $key)) {
            throw new \InvalidArgumentException('Chiave non valida');
        }
        return hash('sha256', $key);
    }

    public static function verifyRecovery(#[\SensitiveParameter] string $key, string $digest): bool
    {
        return preg_match('/\A[0-9a-f]{64}\z/D', $key) === 1 && hash_equals($digest, hash('sha256', $key));
    }
}
