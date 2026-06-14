// path: RankGateInsane/client/src/net/protocol.cpp
#include "protocol.hpp"

#include <cstdio>
#include <stdexcept>

#include "../challenge/proof_builder.hpp"
#include "../challenge/transcript.hpp"
#include "../constants.hpp"
#include "../crypto/base64.hpp"
#include "../crypto/crypto.hpp"
#include "../crypto/kdf.hpp"
#include "../vm/vm.hpp"
#include "binary_frame.hpp"
#include "http_client.hpp"

namespace rg::net {

namespace {

using challenge::Transcript;

struct Keys {
    Bytes c2s, s2c, mac, proof1, sproof1, proof2, seal;
};

Keys derive_keys(const Bytes& prk) {
    auto e = [&](const std::string& info) {
        return crypto::hkdf_expand(prk, str_bytes(info), 32);
    };
    return {e(cfg::HKDF_C2S),    e(cfg::HKDF_S2C),    e(cfg::HKDF_MAC),
            e(cfg::HKDF_PROOF1), e(cfg::HKDF_SPROOF1), e(cfg::HKDF_PROOF2),
            e(cfg::HKDF_SEAL)};
}

Bytes bootstrap_mac_key() { return crypto::sha256(str_bytes(cfg::BOOTSTRAP_MAC_LABEL)); }

// -- frame seal/open helpers (mirror challenge_logic.py) --------------------
Frame plain_seal(Transcript& t, const Bytes& mac_key, uint8_t mt, const Bytes& sid,
                 uint64_t counter, const Bytes& payload) {
    Bytes nonce = crypto::random_bytes(cfg::SZ_NONCE);
    return t.seal_frame(mac_key, mt, sid, counter, nonce, payload,
                        Bytes(cfg::SZ_AUTHTAG, 0));
}

Bytes plain_open(Transcript& t, const Bytes& mac_key, const Frame& f) {
    t.open_frame(mac_key, f);
    return f.encrypted_payload;
}

Frame aead_seal(Transcript& t, const Bytes& mac_key, const Bytes& aead_key, uint8_t mt,
                const Bytes& sid, uint64_t counter, const Bytes& plaintext) {
    Bytes nonce = crypto::random_bytes(cfg::SZ_NONCE);
    Frame hdr;
    hdr.message_type = mt;
    hdr.session_id = sid;
    hdr.counter = counter;
    hdr.nonce = nonce;
    hdr.encrypted_payload = Bytes(plaintext.size(), 0);  // header needs only the length
    Bytes aad = hdr.header();
    Bytes tag;
    Bytes ct = crypto::aead_encrypt(aead_key, nonce, plaintext, aad, tag);
    return t.seal_frame(mac_key, mt, sid, counter, nonce, ct, tag);
}

Bytes aead_open(Transcript& t, const Bytes& mac_key, const Bytes& aead_key,
                const Frame& f) {
    t.open_frame(mac_key, f);
    return crypto::aead_decrypt(aead_key, f.nonce, f.encrypted_payload, f.auth_tag,
                                f.header());
}

// -- transport response decode ----------------------------------------------
Bytes decode_response(const std::string& text) {
    size_t b = 0, e = text.size();
    while (b < e && (text[b] == ' ' || text[b] == '\n' || text[b] == '\r')) ++b;
    while (e > b && (text[e - 1] == ' ' || text[e - 1] == '\n' || text[e - 1] == '\r')) --e;
    std::string s = text.substr(b, e - b);
    if (s.empty()) throw std::runtime_error("empty server response");
    if (s[0] == '{') throw std::runtime_error("server rejected: " + s);
    return crypto::b64decode(s);
}

// -- server public signing key (GET /api/v1/public-key) ---------------------
Bytes parse_pubkey(const std::string& json) {
    size_t k = json.find("public_key");
    if (k == std::string::npos) throw std::runtime_error("public-key: missing field");
    size_t colon = json.find(':', k);
    size_t q1 = json.find('"', colon);
    size_t q2 = json.find('"', q1 + 1);
    if (q1 == std::string::npos || q2 == std::string::npos)
        throw std::runtime_error("public-key: malformed");
    std::string hex = json.substr(q1 + 1, q2 - q1 - 1);
    if (hex.size() % 2 != 0) throw std::runtime_error("public-key: bad hex");
    Bytes out;
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("public-key: bad hex digit");
    };
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nyb(hex[i]) << 4) | nyb(hex[i + 1])));
    return out;
}

void vlog(bool v, const char* fmt) {
    if (v) std::printf("%s\n", fmt);
}

}  // namespace

Bytes run_session(const ProtocolOptions& opt, const Bytes& username_norm,
                  const Bytes& license_struct) {
    HttpClient http(opt.server_url);

    Bytes server_sign_pk = parse_pubkey(http.get("/api/v1/public-key"));
    vlog(opt.verbose, "[*] fetched server Ed25519 public key");

    Bytes bootstrap = bootstrap_mac_key();
    auto kp = crypto::x25519_keypair();
    Bytes client_random = crypto::random_bytes(16);
    Bytes session_id = crypto::random_bytes(cfg::SZ_SESSION_ID);

    // ---- HELLO -------------------------------------------------------------
    Transcript t;
    Bytes hello_payload;
    append(hello_payload, kp.pub);
    append(hello_payload, client_random);
    append(hello_payload, be16(static_cast<uint16_t>(username_norm.size())));
    append(hello_payload, username_norm);
    Frame hello = plain_seal(t, bootstrap, cfg::MT_HELLO, session_id, 1, hello_payload);
    Bytes t1 = t.state();

    std::string resp = http.post("/api/v1/hello", crypto::b64encode(hello.serialize()));
    Frame chal = Frame::parse(decode_response(resp));
    Bytes chal_payload = plain_open(t, bootstrap, chal);
    if (chal_payload.size() < 32 + 16 + 64)
        throw std::runtime_error("server challenge too short");
    Bytes server_pub = slice(chal_payload, 0, 32);
    Bytes server_random = slice(chal_payload, 32, 16);
    Bytes signature = slice(chal_payload, 48, 64);

    Bytes signed_data;
    append(signed_data, str_bytes(cfg::SIGN_CONTEXT));
    append(signed_data, t1);
    append(signed_data, server_pub);
    append(signed_data, server_random);
    if (!crypto::ed25519_verify(server_sign_pk, signed_data, signature))
        throw std::runtime_error("server challenge signature invalid");
    vlog(opt.verbose, "[+] server challenge signature verified");

    // ---- session keys ------------------------------------------------------
    Bytes salt = t.state();  // T2
    Bytes shared = crypto::x25519_shared(kp.priv, server_pub);
    Bytes prk = crypto::hkdf_extract(salt, shared);
    Keys keys = derive_keys(prk);

    // ---- VM ----------------------------------------------------------------
    vm::VMResult vmres = vm::run_vm(username_norm, license_struct, server_random,
                                    session_id, salt, server_random);
    if (opt.verbose)
        std::printf("[+] vm path=0x%08x halt=0x%02x\n", vmres.vm_path_id,
                    vmres.vm_halt_code);

    // ---- CLIENT_PROOF_1 ----------------------------------------------------
    Bytes proof1 = challenge::compute_proof1(keys.proof1, username_norm, license_struct,
                                             vmres, server_random, session_id, salt);
    Bytes p1_payload;
    append(p1_payload, license_struct);
    append(p1_payload, vmres.vm_digest);
    append(p1_payload, vmres.vm_state_hash);
    append(p1_payload, be32(vmres.vm_path_id));
    append(p1_payload, be32(vmres.vm_halt_code));
    append(p1_payload, proof1);
    Frame p1 = aead_seal(t, keys.mac, keys.c2s, cfg::MT_CLIENT_PROOF_1, session_id, 2,
                         p1_payload);
    Bytes t3 = t.state();

    resp = http.post("/api/v1/exchange", crypto::b64encode(p1.serialize()));
    Frame sp = Frame::parse(decode_response(resp));
    Bytes sp_payload = aead_open(t, keys.mac, keys.s2c, sp);
    if (sp_payload.size() != 48) throw std::runtime_error("bad server proof1 length");
    Bytes server_proof1 = slice(sp_payload, 0, 32);
    Bytes server_challenge2 = slice(sp_payload, 32, 16);

    Bytes sp1_in;
    append(sp1_in, str_bytes(cfg::SPROOF1_LABEL));
    append(sp1_in, t3);
    append(sp1_in, vmres.vm_digest);
    append(sp1_in, server_challenge2);
    if (!crypto::ct_equal(server_proof1, crypto::hmac_sha256(keys.sproof1, sp1_in)))
        throw std::runtime_error("server proof1 invalid");
    vlog(opt.verbose, "[+] server proof1 verified");

    // ---- CLIENT_PROOF_2 / FINALIZE ----------------------------------------
    Bytes proof2 = challenge::compute_proof2(keys.proof2, server_challenge2,
                                             server_random, server_pub, vmres.vm_digest,
                                             salt);
    Frame p2 = aead_seal(t, keys.mac, keys.c2s, cfg::MT_CLIENT_PROOF_2, session_id, 3,
                         proof2);
    Bytes t5 = t.state();

    resp = http.post("/api/v1/finalize", crypto::b64encode(p2.serialize()));
    Frame sealed = Frame::parse(decode_response(resp));
    Bytes inner_blob = aead_open(t, keys.mac, keys.s2c, sealed);
    if (inner_blob.size() < cfg::SZ_NONCE + cfg::SZ_AUTHTAG)
        throw std::runtime_error("sealed blob too short");

    Bytes seal_nonce = slice(inner_blob, 0, cfg::SZ_NONCE);
    size_t ct_len = inner_blob.size() - cfg::SZ_NONCE - cfg::SZ_AUTHTAG;
    Bytes inner_ct = slice(inner_blob, cfg::SZ_NONCE, ct_len);
    Bytes inner_tag = slice(inner_blob, cfg::SZ_NONCE + ct_len, cfg::SZ_AUTHTAG);

    Bytes k_seal = crypto::hkdf(t5, keys.seal, str_bytes(cfg::SEAL_INFO), 32);
    return crypto::aead_decrypt(k_seal, seal_nonce, inner_ct, inner_tag, t5);
}

}  // namespace rg::net
