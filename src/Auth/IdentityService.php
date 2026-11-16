<?php
declare(strict_types=1);
namespace VenVia\Auth;
require_once __DIR__.'/Secrets.php';

final class IdentityService
{
    public function __construct(private readonly \PDO $db) {
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false);
    }
    private function query(string $sql, array $args = []): \PDOStatement {
        $q = $this->db->prepare($sql);
        $q->execute($args);
        return $q;
    }
    private function transaction(callable $fn): mixed {
        $this->db->beginTransaction();
        try { $result = $fn(); $this->db->commit(); return $result; }
        catch (\Throwable $e) { if ($this->db->inTransaction()) $this->db->rollBack(); throw $e; }
    }
    private function lock(): void {
        if (!$this->query('SELECT id FROM vv_auth_guard WHERE id=1 FOR UPDATE')->fetchColumn()) {
            throw new \RuntimeException('Authentication schema not initialized');
        }
    }
    private function audit(?int $actor, ?int $target, string $action): void {
        $this->query('INSERT INTO vv_auth_audit(actor_id,target_id,action) VALUES (?,?,?)', [$actor,$target,$action]);
    }
    private function throttle(string $scope, int $limit): bool {
        $this->query('INSERT IGNORE INTO vv_auth_limits(scope,attempts,window_start) VALUES (?,0,UTC_TIMESTAMP())',[$scope]);
        $this->query('UPDATE vv_auth_limits SET attempts=0,window_start=UTC_TIMESTAMP() WHERE scope=? AND window_start < UTC_TIMESTAMP() - INTERVAL 15 MINUTE',[$scope]);
        $n=(int)$this->query('SELECT attempts FROM vv_auth_limits WHERE scope=? FOR UPDATE',[$scope])->fetchColumn();
        if ($n >= $limit) return false;
        $this->query('UPDATE vv_auth_limits SET attempts=attempts+1 WHERE scope=?',[$scope]);
        return true;
    }
    private function user(int $id): array {
        $u=$this->query('SELECT * FROM vv_auth_users WHERE id=?',[$id])->fetch(\PDO::FETCH_ASSOC);
        if (!$u || !$u['active']) throw new \RuntimeException('Access denied');
        return $u;
    }
    private function sessionUser(#[\SensitiveParameter] string $token, bool $allowReset=false): array {
        if (!preg_match('/\A[0-9a-f]{64}\z/D',$token)) throw new \RuntimeException('Access denied');
        $id=$this->query('SELECT s.user_id FROM vv_auth_sessions s JOIN vv_auth_users u ON u.id=s.user_id WHERE s.digest=? AND s.expires_at>UTC_TIMESTAMP() AND u.active=1 AND s.epoch=u.epoch',[hash('sha256',$token)])->fetchColumn();
        if (!$id) throw new \RuntimeException('Access denied');
        $u=$this->user((int)$id);
        if ($u['must_change'] && !$allowReset) throw new \RuntimeException('Password change required');
        return $u;
    }
    public function authenticate(string $username, #[\SensitiveParameter] string $password): ?string {
        return $this->transaction(function() use ($username,$password) {
            $this->lock();
            // A global bound prevents unbounded per-username entries and guessing.
            if (!$this->throttle('login-global',60)) return null;
            if (!preg_match('/\A[a-zA-Z0-9_.-]{3,64}\z/D',$username)) return null;
            $u=$this->query('SELECT * FROM vv_auth_users WHERE username=?',[$username])->fetch(\PDO::FETCH_ASSOC);
            if (!$u || !$u['active']) return null;
            if (!$this->throttle('user:'.$u['id'],5)) return null;
            if (!Secrets::verifyPassword($password,$u['password_hash'])) { $this->audit(null,(int)$u['id'],'login_failed'); return null; }
            $this->query('DELETE FROM vv_auth_limits WHERE scope=?',['user:'.$u['id']]);
            $token=bin2hex(random_bytes(32));
            $this->query('INSERT INTO vv_auth_sessions(digest,user_id,epoch,expires_at) VALUES (?,?,?,UTC_TIMESTAMP()+INTERVAL 8 HOUR)',[hash('sha256',$token),$u['id'],$u['epoch']]);
            $this->audit((int)$u['id'],(int)$u['id'],'login');
            return $token;
        });
    }
    public function authorize(#[\SensitiveParameter] string $token): array {
        $u=$this->sessionUser($token);
        return ['id'=>(int)$u['id'],'role'=>$u['role']];
    }
    private function invalidate(int $id): void {
        $this->query('UPDATE vv_auth_users SET epoch=epoch+1 WHERE id=?',[$id]);
        $this->query('DELETE FROM vv_auth_sessions WHERE user_id=?',[$id]);
    }
    public function changePassword(#[\SensitiveParameter] string $token, #[\SensitiveParameter] string $current, #[\SensitiveParameter] string $next): void {
        $this->transaction(function() use ($token,$current,$next) {
            $this->lock(); $u=$this->sessionUser($token,true);
            if (!Secrets::verifyPassword($current,$u['password_hash'])) throw new \RuntimeException('Access denied');
            $id=(int)$u['id'];
            $this->query('UPDATE vv_auth_users SET password_hash=?,must_change=0 WHERE id=?',[Secrets::passwordHash($next),$id]);
            $this->invalidate($id); $this->audit($id,$id,'password_change');
        });
    }
    private function mayManage(array $actor,array $target): bool {
        // Conservative initial role mapping; no authority over technical identity.
        return $target['role'] !== 'technical' && $actor['id'] !== $target['id'] &&
            ($actor['role']==='technical' || ($actor['role']==='operational' && $target['role']==='user'));
    }
    public function resetOrRevoke(#[\SensitiveParameter] string $token,int $targetId,#[\SensitiveParameter] ?string $temporaryPassword): void {
        $this->transaction(function() use ($token,$targetId,$temporaryPassword) {
            $this->lock(); $actor=$this->sessionUser($token); $target=$this->user($targetId);
            if (!$this->mayManage($actor,$target)) throw new \RuntimeException('Access denied');
            if ($temporaryPassword===null) $this->query('UPDATE vv_auth_users SET active=0 WHERE id=?',[$targetId]);
            else $this->query('UPDATE vv_auth_users SET password_hash=?,must_change=1 WHERE id=?',[Secrets::passwordHash($temporaryPassword),$targetId]);
            $this->invalidate($targetId); $this->audit((int)$actor['id'],$targetId,$temporaryPassword===null?'revocation':'password_reset');
        });
    }
    public function recoverTechnical(#[\SensitiveParameter] string $key,#[\SensitiveParameter] string $next): ?string {
        return $this->transaction(function() use ($key,$next) {
            $this->lock();
            if (!$this->throttle('technical-recovery',5)) return null;
            $u=$this->query("SELECT * FROM vv_auth_users WHERE role='technical' AND active=1")->fetch(\PDO::FETCH_ASSOC);
            if (!$u || !Secrets::verifyRecovery($key,(string)$u['recovery_digest'])) return null;
            $replacement=Secrets::newRecoveryKey(); $id=(int)$u['id'];
            $this->query('UPDATE vv_auth_users SET password_hash=?,recovery_digest=?,must_change=0 WHERE id=?',[Secrets::passwordHash($next),Secrets::recoveryDigest($replacement),$id]);
            $this->invalidate($id); $this->audit($id,$id,'technical_recovery');
            return $replacement;
        });
    }
}
