<?php
declare(strict_types=1);
require_once __DIR__.'/../src/Auth/Secrets.php';
use VenVia\Auth\Secrets;
function check(bool $ok): void { if (!$ok) throw new RuntimeException('Test failed'); }
$password='test passphrase only 2026';
$hash=Secrets::passwordHash($password);
check($hash!==$password);
check(Secrets::verifyPassword($password,$hash));
check(!Secrets::verifyPassword('incorrect',$hash));
try { Secrets::passwordHash('short'); throw new RuntimeException('Short password accepted'); }
catch (InvalidArgumentException) {}
$key=Secrets::newRecoveryKey();
$digest=Secrets::recoveryDigest($key);
check(strlen($key)===64 && $key!==$digest);
check(Secrets::verifyRecovery($key,$digest));
check(!Secrets::verifyRecovery(Secrets::newRecoveryKey(),$digest));
check(!Secrets::verifyRecovery('invalid',$digest));
echo "Offline secret primitives passed\n";
