// path: RankGateInsane/client/src/vm/vm.cpp
#include "vm.hpp"

#include <array>
#include <stdexcept>

#include "../constants.hpp"
#include "../crypto/crypto.hpp"
#include "bytecode.hpp"
#include "opcodes.hpp"

namespace rg::vm {

namespace {

// -- 64-bit helpers (match vm_reference.py exactly) -------------------------
inline uint64_t rotl64(uint64_t x, unsigned n) {
    n &= 63;
    return n ? ((x << n) | (x >> (64 - n))) : x;
}
inline uint64_t rotr64(uint64_t x, unsigned n) {
    n &= 63;
    return n ? ((x >> n) | (x << (64 - n))) : x;
}
inline uint64_t hash_round(uint64_t a, uint64_t b) {
    uint64_t x = a ^ rotl64(b, 17);
    x = x * 0x9E3779B97F4A7C15ULL;
    x ^= x >> 31;
    x = x + rotl64(a, 13);
    x ^= rotr64(x, 7);
    return x;
}
inline uint64_t mix(uint64_t acc, uint64_t val, unsigned rd) {
    uint64_t rotated = rotl64(val, (rd * 7 + 13) & 63);
    return acc + (rotated ^ 0xD1B54A32D192ED03ULL);
}

std::vector<uint64_t> words_from(const Bytes& data, size_t nwords) {
    Bytes padded = data;
    padded.resize(nwords * 8, 0);
    std::vector<uint64_t> out(nwords);
    for (size_t i = 0; i < nwords; ++i) out[i] = rd_be64(&padded[i * 8]);
    return out;
}

std::vector<uint64_t> pack_inputs(const Bytes& username_norm,
                                  const Bytes& license_struct,
                                  const Bytes& server_random,
                                  const Bytes& session_id,
                                  const Bytes& transcript_prefix) {
    std::vector<uint64_t> mem(cfg::VM_MEM_WORDS, 0);
    Bytes uname = username_norm;
    if (uname.size() > cfg::VM_USERNAME_CAP) uname.resize(cfg::VM_USERNAME_CAP);
    mem[0] = uname.size();
    auto uw = words_from(uname, 8);
    for (size_t i = 0; i < 8; ++i) mem[1 + i] = uw[i];
    auto lw = words_from(license_struct, 4);
    for (size_t i = 0; i < 4; ++i) mem[9 + i] = lw[i];
    auto sr = words_from(server_random, 2);
    mem[13] = sr[0];
    mem[14] = sr[1];
    auto sid = words_from(session_id, 2);
    mem[15] = sid[0];
    mem[16] = sid[1];
    auto tp = words_from(transcript_prefix, 4);
    for (size_t i = 0; i < 4; ++i) mem[17 + i] = tp[i];
    Bytes vmin = crypto::blake2b(str_bytes(cfg::VM_INPUT_DOMAIN), 8);
    mem[21] = rd_be64(vmin.data());
    return mem;
}

// Per-session bijection over the 256 dispatch slots (anti-dynamic-analysis
// flavor). Semantics are unchanged, so client and server agree; a hardened
// build wires this into an indirect dispatch table. Kept for fidelity.
std::array<int, 256> handler_permutation(const Bytes& session_nonce) {
    std::array<int, 256> perm{};
    for (int i = 0; i < 256; ++i) perm[i] = i;
    Bytes seed = crypto::blake2b(cat({str_bytes(cfg::VM_PERM_LABEL), session_nonce}), 32);
    Bytes ks = crypto::blake2b_ctr_keystream(seed, 256 * 2,
                                             str_bytes(cfg::VM_PERM_KS_DOMAIN));
    for (int i = 255; i > 0; --i) {
        int j = (((ks[2 * i] << 8) | ks[2 * i + 1]) % (i + 1));
        std::swap(perm[i], perm[j]);
    }
    return perm;
}

Bytes load_bytecode() {
    Bytes blob(kEncryptedBlob, kEncryptedBlob + kEncryptedBlobLen);
    Bytes key = crypto::blake2b(str_bytes(cfg::VM_BLOB_KEY_LABEL), 32);
    return crypto::stream_xor(key, blob, str_bytes(cfg::VM_BLOB_DOMAIN));
}

constexpr uint64_t M32 = 0xFFFFFFFFULL;

class VM {
public:
    using Handler = void (VM::*)(uint8_t);

    VM(Bytes code, std::vector<uint64_t> mem, const Bytes& session_nonce)
        : code_(std::move(code)), mem_(std::move(mem)) {
        reg_.fill(0);
        perm_ = handler_permutation(session_nonce);
        build_dispatch_table();  // indirect dispatch permuted by the session nonce
    }

    VMResult run() {
        size_t steps = 0;
        while (!halted_) {
            if (steps >= kMaxSteps) {
                halt_operand_ = 0xEE;
                break;
            }
            ++steps;
            uint8_t op = u8();
            // Indirect dispatch through the per-session permuted handler table:
            // table_[perm_[op]] == handler_for(op), so semantics are identical
            // to a direct switch, but the dispatch slot differs per session.
            (this->*table_[perm_[op]])(op);
        }
        return finish();
    }

private:
    static constexpr size_t kMaxSteps = 200000;

    Bytes code_;
    std::vector<uint64_t> mem_;
    std::array<uint64_t, 16> reg_{};
    std::vector<uint64_t> stack_;
    std::array<int, 256> perm_{};
    std::array<Handler, 256> table_{};
    uint8_t flags_ = 0;
    size_t ip_ = 0;
    uint32_t path_ = 0x811C9DC5;
    bool halted_ = false;
    uint8_t halt_operand_ = 0;

    // -- fetch -------------------------------------------------------------
    uint8_t u8() {
        if (ip_ >= code_.size()) throw std::runtime_error("vm: ip out of range");
        return code_[ip_++];
    }
    uint16_t u16() {
        if (ip_ + 2 > code_.size()) throw std::runtime_error("vm: u16 oob");
        uint16_t v = static_cast<uint16_t>((code_[ip_] << 8) | code_[ip_ + 1]);
        ip_ += 2;
        return v;
    }
    uint64_t u64() {
        if (ip_ + 8 > code_.size()) throw std::runtime_error("vm: u64 oob");
        uint64_t v = rd_be64(&code_[ip_]);
        ip_ += 8;
        return v;
    }
    uint64_t& R(uint8_t i) {
        if (i >= 16) throw std::runtime_error("vm: register index oob");
        return reg_[i];
    }

    // -- flags -------------------------------------------------------------
    void set_cmp_flags(uint64_t a, uint64_t b) {
        uint64_t diff = a - b;
        flags_ = 0;
        if (a == b) flags_ |= FL_ZF;
        if (a < b) flags_ |= FL_CF;
        if (diff >> 63) flags_ |= FL_SF;
    }
    bool cond(uint8_t code) {
        bool z = flags_ & FL_ZF, c = flags_ & FL_CF, s = flags_ & FL_SF;
        switch (code) {
            case COND_ZF: return z;
            case COND_NZF: return !z;
            case COND_CF: return c;
            case COND_NCF: return !c;
            case COND_SF: return s;
            case COND_NSF: return !s;
            default: throw std::runtime_error("vm: bad cond");
        }
    }
    void fold_path(bool taken) {
        path_ = static_cast<uint32_t>((static_cast<uint64_t>(path_) * 0x01000193ULL) ^
                                      (ip_ & 0xFFFF) ^ (taken ? 1u : 0u)) ;
    }

    // -- handlers (one method per opcode group; behavior identical to a direct
    //    switch). Dispatched indirectly via the permuted table_. --------------
    void h_nop(uint8_t) {}
    void h_mov_ri(uint8_t) { uint8_t rd = u8(); uint64_t imm = u64(); R(rd) = imm; }
    void h_mov_rr(uint8_t) { uint8_t rd = u8(), rs = u8(); R(rd) = R(rs); }
    void h_load(uint8_t) {
        uint8_t rd = u8(), areg = u8();
        R(rd) = mem_[R(areg) % cfg::VM_MEM_WORDS];
    }
    void h_store(uint8_t) {
        uint8_t areg = u8(), rs = u8();
        mem_[R(areg) % cfg::VM_MEM_WORDS] = R(rs);
    }
    void h_alu3(uint8_t op) {
        uint8_t rd = u8(), ra = u8(), rb = u8();
        uint64_t a = R(ra), b = R(rb);
        switch (op) {
            case ADD: R(rd) = a + b; break;
            case SUB: R(rd) = a - b; break;
            case MUL: R(rd) = a * b; break;
            case XOR: R(rd) = a ^ b; break;
            case AND: R(rd) = a & b; break;
            default:  R(rd) = a | b; break;  // OR
        }
    }
    void h_not(uint8_t) { uint8_t rd = u8(), ra = u8(); R(rd) = ~R(ra); }
    void h_shift(uint8_t op) {
        uint8_t rd = u8(), ra = u8(), imm = u8();
        uint64_t a = R(ra);
        switch (op) {
            case ROL: R(rd) = rotl64(a, imm); break;
            case ROR: R(rd) = rotr64(a, imm); break;
            case SHL: R(rd) = (imm & 63) ? (a << (imm & 63)) : a; break;
            default:  R(rd) = (imm & 63) ? (a >> (imm & 63)) : a; break;  // SHR
        }
    }
    void h_cmp(uint8_t) { uint8_t ra = u8(), rb = u8(); set_cmp_flags(R(ra), R(rb)); }
    void h_cmov(uint8_t) {
        uint8_t rd = u8(), rs = u8(), c = u8();
        if (cond(c)) R(rd) = R(rs);
    }
    void h_jmp(uint8_t) { uint16_t addr = u16(); ip_ = addr; }
    void h_jcc(uint8_t op) {
        uint16_t addr = u16();
        bool taken = (op == JZ) ? (flags_ & FL_ZF) : !(flags_ & FL_ZF);
        fold_path(taken);
        if (taken) ip_ = addr;
    }
    void h_call(uint8_t) { uint16_t addr = u16(); stack_.push_back(ip_); ip_ = addr; }
    void h_ret(uint8_t) {
        if (stack_.empty()) throw std::runtime_error("vm: RET underflow");
        ip_ = static_cast<size_t>(stack_.back());
        stack_.pop_back();
    }
    void h_hash(uint8_t) { uint8_t rd = u8(), ra = u8(), rb = u8(); R(rd) = hash_round(R(ra), R(rb)); }
    void h_mix(uint8_t) { uint8_t rd = u8(), ra = u8(); R(rd) = mix(R(rd), R(ra), rd); }
    void h_halt(uint8_t) { halt_operand_ = u8(); halted_ = true; }
    void h_unknown(uint8_t) { halt_operand_ = 0xFD; halted_ = true; }

    void build_dispatch_table() {
        table_.fill(&VM::h_unknown);
        auto set = [&](uint8_t op, Handler h) { table_[perm_[op]] = h; };
        set(NOP, &VM::h_nop);
        set(MOV_RI, &VM::h_mov_ri);
        set(MOV_RR, &VM::h_mov_rr);
        set(LOAD, &VM::h_load);
        set(STORE, &VM::h_store);
        for (uint8_t op : {ADD, SUB, MUL, XOR, AND, OR}) set(op, &VM::h_alu3);
        set(NOT, &VM::h_not);
        for (uint8_t op : {ROL, ROR, SHL, SHR}) set(op, &VM::h_shift);
        set(CMP, &VM::h_cmp);
        set(CMOV, &VM::h_cmov);
        set(JMP, &VM::h_jmp);
        set(JZ, &VM::h_jcc);
        set(JNZ, &VM::h_jcc);
        set(CALL, &VM::h_call);
        set(RET, &VM::h_ret);
        set(HASH_ROUND, &VM::h_hash);
        set(MIX, &VM::h_mix);
        set(HALT, &VM::h_halt);
    }

    VMResult finish() {
        Bytes digest;
        for (int i = 0; i < 4; ++i) append(digest, be64(reg_[12 + i]));
        Bytes state;
        for (uint64_t r : reg_) append(state, be64(r));
        for (uint64_t s : stack_) append(state, be64(s));
        state.push_back(flags_ & 0xFF);
        append(state, be16(static_cast<uint16_t>(ip_ & 0xFFFF)));
        append(state, be32(path_));
        Bytes state_hash = crypto::blake2b(state, 32);
        uint32_t halt_code = static_cast<uint32_t>((halt_operand_ ^ (path_ & 0xFF)) & M32);
        return VMResult{digest, state_hash, path_, halt_code};
    }
};

}  // namespace

VMResult run_vm(const Bytes& username_norm, const Bytes& license_struct,
                const Bytes& server_random, const Bytes& session_id,
                const Bytes& transcript_prefix, const Bytes& session_nonce) {
    auto mem = pack_inputs(username_norm, license_struct, server_random, session_id,
                           transcript_prefix);
    VM vm(load_bytecode(), std::move(mem), session_nonce);
    return vm.run();
}

}  // namespace rg::vm
