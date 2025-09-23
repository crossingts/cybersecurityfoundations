# Replay attacks and anti-replay methods — Quiz

### Replay attacks and anti-replay methods

**1. What is the primary goal of a replay attack? (Choose one answer)**\
a) To break encryption algorithms through brute force\
b) To overload a network with traffic and cause a denial of service\
**c) To intercept and retransmit valid data to gain unauthorized access or disrupt services**\
d) To physically damage network hardware

**2. Which anti-replay method involves the receiver maintaining a sliding window of accepted packets to detect and discard duplicates? (Choose one answer)**\
a) Cryptographic hashes\
**b) Sequence number windowing**\
c) Rotating secret keys\
d) Nonces

**3. How does TLS 1.3 significantly mitigate session replay attacks compared to TLS 1.2? (Choose one answer)**\
a) By using much larger sequence numbers\
b) By completely eliminating all encryption\
**c) By implementing one-time-use session tickets and non-replayable handshakes**\
d) By relying solely on the application layer for security

**4. A replay attack that uses a captured session cookie to impersonate a user is best classified as what type of attack? (Choose one answer)**\
a) A network-level replay attack\
**b) A Session replay attack**\
c) A Cryptographic hash attack\
d) A Denial-of-Service attack

**5. Why are application-layer defenses like idempotency keys still necessary even when using TLS 1.3? (Choose one answer)**\
a) Because TLS 1.3 has no built-in anti-replay protections\
b) To prevent attackers from breaking the encryption\
**c) To protect against the replayed duplication of actions (e.g., a financial transaction) that the protocol itself cannot prevent**\
d) To increase the speed of the encryption process