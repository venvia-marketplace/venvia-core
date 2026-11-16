<?php
declare(strict_types=1);

// Local CLI only. Credentials are supplied through an ACL-protected JSON file
// outside the web root. Never print database errors or secrets.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
$checks = [];
$checks['php_version'] = PHP_VERSION;
$checks['sapi'] = PHP_SAPI;
$extensions = ['pdo_mysql', 'openssl', 'mbstring', 'curl', 'zip', 'fileinfo'];
$missing = array_values(array_filter($extensions, static fn(string $e): bool => !extension_loaded($e)));
$checks['missing_extensions'] = $missing;
$checks['php_ok'] = PHP_VERSION_ID >= 80500 && $missing === [];
$checks['database_ok'] = false;
try {
    if ($argc !== 2 || !is_file($argv[1])) {
        throw new RuntimeException('config missing');
    }
    $raw = file_get_contents($argv[1], false, null, 0, 65537);
    if ($raw === false || strlen($raw) > 65536) {
        throw new RuntimeException('invalid config');
    }
    $cfg = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($cfg) || ($cfg['host'] ?? null) !== '127.0.0.1'
        || !is_string($cfg['user'] ?? null) || !is_string($cfg['password'] ?? null)
        || !is_string($cfg['database'] ?? null) || !preg_match('/^[a-zA-Z0-9_]+$/D', $cfg['database'])) {
        throw new RuntimeException('invalid config');
    }
    $port = $cfg['port'] ?? 3306;
    if (!is_int($port) || $port < 1 || $port > 65535) {
        throw new RuntimeException('invalid port');
    }
    $pdo = new PDO('mysql:host=127.0.0.1;port='.$port.';dbname='.$cfg['database'].';charset=utf8mb4',
        $cfg['user'], $cfg['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 3,
        ]);
    $checks['database_ok'] = (string)$pdo->query('SELECT 1')->fetchColumn() === '1';
} catch (Throwable) {
    $checks['database_detail'] = 'Authenticated database probe unavailable or failed';
}
$checks['ok'] = $checks['php_ok'] && $checks['database_ok'];
echo json_encode($checks, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR).PHP_EOL;
exit($checks['ok'] ? 0 : 1);
