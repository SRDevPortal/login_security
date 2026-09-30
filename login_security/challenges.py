"""JSON challenges and atomic operations on a dedicated, site-scoped Redis namespace.

Use the raw Redis client: Frappe's cache helpers can suppress connectivity errors
and maintain request-local copies, neither of which is suitable for auth state.
"""

import json
import secrets
import time

from login_security.crypto import digest


class ChallengeError(Exception):
    def __init__(self, code, *, category=None, retry_after=None):
        super().__init__(code)
        self.category = category
        self.retry_after = retry_after


RATE_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return n <= tonumber(ARGV[1]) and 1 or 0
"""

VERIFY_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 'expired' end
local c = cjson.decode(raw)
if c.binding ~= ARGV[1] or c.purpose ~= ARGV[2] then return 'invalid' end
local now = tonumber(ARGV[4])
if c.expires_at <= now or c.transaction_expires_at <= now then return 'expired' end
if c.attempts >= c.max_attempts then return 'exhausted' end
if c.code_digest ~= ARGV[3] then
    c.attempts = c.attempts + 1
    redis.call('SET', KEYS[1], cjson.encode(c), 'KEEPTTL')
    return 'incorrect'
end
redis.call('DEL', KEYS[1])
return raw
"""

RESEND_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 'expired' end
local c = cjson.decode(raw)
if c.binding ~= ARGV[1] or c.purpose ~= ARGV[2] then return 'invalid' end
local now = tonumber(ARGV[4])
if c.transaction_expires_at <= now then return 'expired' end
if c.attempts >= c.max_attempts then return 'exhausted' end
if c.last_sent_at + tonumber(ARGV[5]) > now then return 'cooldown' end
c.last_sent_at = now
c.code_digest = ARGV[3]
c.expires_at = math.min(now + tonumber(ARGV[6]), c.transaction_expires_at)
c.resends = c.resends + 1
redis.call('SET', KEYS[1], cjson.encode(c), 'KEEPTTL')
return cjson.encode(c)
"""


class ChallengeStore:
    def __init__(self, client, site, secret, clock=time.time):
        self.client, self.site, self.secret, self.clock = client, site, secret, clock
        self.prefix = "login_security:" + digest(secret, "site", site) + ":"

    def key(self, challenge_id):
        if not isinstance(challenge_id, str) or len(challenge_id) != 43:
            raise ChallengeError("invalid")
        return self.prefix + "challenge:" + challenge_id

    def code_digest(self, challenge_id, code):
        return digest(self.secret, "code", self.site, challenge_id, code)

    def binding(self, nonce):
        return digest(self.secret, "binding", self.site, nonce)

    def rate(self, category, identity, limit, seconds):
        key = self.prefix + "rate:" + digest(self.secret, category, identity)
        if not self.client.eval(RATE_SCRIPT, 1, key, limit, seconds):
            raise ChallengeError("rate_limited", category=category, retry_after=max(1, self.client.ttl(key)))

    def create(self, *, purpose, binding, code, context, ttl=300, lifetime=600, max_attempts=5):
        challenge_id = secrets.token_urlsafe(32)
        now = int(self.clock())
        record = dict(
            context,
            purpose=purpose,
            binding=self.binding(binding),
            code_digest=self.code_digest(challenge_id, code),
            created_at=now,
            expires_at=now + min(ttl, lifetime),
            transaction_expires_at=now + lifetime,
            attempts=0,
            max_attempts=max_attempts,
            last_sent_at=now,
            resends=0,
        )
        self.client.set(self.key(challenge_id), json.dumps(record), ex=lifetime, nx=True)
        return challenge_id, record

    def read(self, challenge_id, binding, purpose):
        raw = self.client.get(self.key(challenge_id))
        if not raw:
            raise ChallengeError("expired")
        record = json.loads(raw)
        import hmac

        if not hmac.compare_digest(record["binding"], self.binding(binding)) or record["purpose"] != purpose:
            raise ChallengeError("invalid")
        if record["transaction_expires_at"] <= self.clock():
            raise ChallengeError("expired")
        return record

    def _decode(self, result):
        result = result.decode() if isinstance(result, bytes) else result
        if not result.startswith("{"):
            raise ChallengeError(result)
        return json.loads(result)

    def verify(self, challenge_id, binding, purpose, code):
        # Digest is fixed-size regardless of user input; never send the code to Redis.
        return self._decode(
            self.client.eval(
                VERIFY_SCRIPT,
                1,
                self.key(challenge_id),
                self.binding(binding),
                purpose,
                self.code_digest(challenge_id, code),
                int(self.clock()),
            )
        )

    def resend(self, challenge_id, binding, purpose, code, cooldown=60, ttl=300):
        return self._decode(
            self.client.eval(
                RESEND_SCRIPT,
                1,
                self.key(challenge_id),
                self.binding(binding),
                purpose,
                self.code_digest(challenge_id, code),
                int(self.clock()),
                cooldown,
                ttl,
            )
        )

    def cancel(self, challenge_id):
        self.client.delete(self.key(challenge_id))

    def invalidate_code(self, challenge_id, code):
        # Compare-and-update inside Redis; do not resurrect a consumed transaction.
        self.client.eval(
            """
            local raw = redis.call('GET', KEYS[1])
            if not raw then return 0 end
            local c = cjson.decode(raw)
            if c.code_digest ~= ARGV[1] then return 0 end
            c.code_digest = ''
            redis.call('SET', KEYS[1], cjson.encode(c), 'KEEPTTL')
            return 1
        """,
            1,
            self.key(challenge_id),
            self.code_digest(challenge_id, code),
        )

    def consume_for_recovery(self, challenge_id, binding):
        result = self.client.eval(
            """
            local raw = redis.call('GET', KEYS[1])
            if not raw then return 'expired' end
            local c = cjson.decode(raw)
            if c.binding ~= ARGV[1] or c.purpose ~= 'staff_login' then return 'invalid' end
            if c.transaction_expires_at <= tonumber(ARGV[2]) then return 'expired' end
            redis.call('DEL', KEYS[1])
            return raw
        """,
            1,
            self.key(challenge_id),
            self.binding(binding),
            int(self.clock()),
        )
        return self._decode(result)
