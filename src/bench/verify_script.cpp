// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bench/bench.h>
#include <coins.h>
#include <key.h>
#include <policy/policy.h>
#include <prevector.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/verify_flags.h>
#include <span.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>
#include <util/check.h>
#include <util/translation.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <vector>

enum class ScriptType {
    P2WPKH,          // segwitv0, witness-pubkey-hash (ECDSA signature)
    P2SH_P2WPKH,     // nested segwitv0, pay-to-script-hash wrapping a witness-pubkey-hash (ECDSA signature)
    P2TR_KeyPath,    // segwitv1, taproot key-path spend (Schnorr signature)
    P2TR_ScriptPath, // segwitv1, taproot script-path spend (Tapscript leaf with a single OP_CHECKSIG)
};

static size_t ExpectedWitnessStackSize(ScriptType script_type)
{
    switch (script_type) {
    case ScriptType::P2WPKH: return 2; // [pubkey, signature]
    case ScriptType::P2SH_P2WPKH: return 2;  // [pubkey, signature]
    case ScriptType::P2TR_KeyPath: return 1; // [signature]
    case ScriptType::P2TR_ScriptPath: return 3; // [signature, tapscript, control block]
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

// Microbenchmark for verification of standard scripts.
static void VerifyScriptBench(benchmark::Bench& bench, ScriptType script_type)
{
    ECC_Context ecc_context{};

    // Create deterministic key material needed for output script creation / signing
    CKey privkey;
    privkey.Set(uint256::ONE.begin(), uint256::ONE.end(), /*fCompressedIn=*/true);
    CPubKey pubkey = privkey.GetPubKey();
    XOnlyPubKey xonly_pubkey{pubkey};
    CKeyID key_id = pubkey.GetID();

    // The witness program that a nested segwit output commits to: OP_0 <keyhash>.
    const CScript p2wpkh_program{GetScriptForDestination(WitnessV0KeyHash(pubkey))};

    FlatSigningProvider keystore;
    keystore.keys.emplace(key_id, privkey);
    keystore.pubkeys.emplace(key_id, pubkey);

    // Create crediting and spending transactions with provided input type
    const auto dest{[&]() -> CTxDestination {
        switch (script_type) {
        case ScriptType::P2WPKH: return WitnessV0KeyHash(pubkey);
        case ScriptType::P2SH_P2WPKH: {
            const ScriptHash script_hash{p2wpkh_program};
            keystore.scripts.emplace(ToScriptID(script_hash), p2wpkh_program);
            return script_hash;
        }
        case ScriptType::P2TR_KeyPath: return WitnessV1Taproot(xonly_pubkey);
        case ScriptType::P2TR_ScriptPath:
            TaprootBuilder builder;
            builder.Add(0, CScript() << ToByteVector(xonly_pubkey) << OP_CHECKSIG, TAPROOT_LEAF_TAPSCRIPT);
            builder.Finalize(XOnlyPubKey::NUMS_H); // effectively unspendable key-path
            const auto output{builder.GetOutput()};
            keystore.tr_trees.emplace(output, builder);
            return output;
        } // no default case, so the compiler can warn about missing cases
        assert(false);
    }()};
    const CMutableTransaction& txCredit = BuildCreditingTransaction(GetScriptForDestination(dest), 1);
    CMutableTransaction txSpend = BuildSpendingTransaction(/*scriptSig=*/{}, /*scriptWitness=*/{}, CTransaction(txCredit));

    // Sign spending transaction, precompute transaction data
    PrecomputedTransactionData txdata;
    {
        const std::map<COutPoint, Coin> coins{
            {txSpend.vin[0].prevout, Coin(txCredit.vout[0], /*nHeightIn=*/100, /*fCoinBaseIn=*/false)}
        };
        std::map<int, bilingual_str> input_errors;
        bool complete = SignTransaction(txSpend, &keystore, coins, {.sighash_type = SIGHASH_ALL}, input_errors);
        assert(complete);
        // Weak sanity check on witness data to ensure we produced the intended spending type
        assert(txSpend.vin[0].scriptWitness.stack.size() == ExpectedWitnessStackSize(script_type));
        // A nested segwit spend additionally carries the witness program as the single scriptSig
        // push that VerifyScript requires for a P2SH witness spend; others must be empty.
        if (script_type == ScriptType::P2SH_P2WPKH) {
            assert(txSpend.vin[0].scriptSig == (CScript() << std::vector<unsigned char>(p2wpkh_program.begin(), p2wpkh_program.end())));
        } else {
            assert(txSpend.vin[0].scriptSig.empty());
        }
        txdata.Init(txSpend, /*spent_outputs=*/{txCredit.vout[0]});
    }

    // Benchmark.
    bench.unit("script").run([&] {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL),
            &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);
    });
}

static void VerifyScriptP2WPKH(benchmark::Bench& bench) { VerifyScriptBench(bench, ScriptType::P2WPKH); }
static void VerifyScriptP2SH_P2WPKH(benchmark::Bench& bench) { VerifyScriptBench(bench, ScriptType::P2SH_P2WPKH); }
static void VerifyScriptP2TR_KeyPath(benchmark::Bench& bench) { VerifyScriptBench(bench, ScriptType::P2TR_KeyPath); }
static void VerifyScriptP2TR_ScriptPath(benchmark::Bench& bench) { VerifyScriptBench(bench, ScriptType::P2TR_ScriptPath); }

static void VerifyNestedIfScript(benchmark::Bench& bench)
{
    std::vector<ScriptStackElem> stack;
    CScript script;
    for (int i = 0; i < 100; ++i) {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i) {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i) {
        script << OP_ENDIF;
    }
    bench.unit("script")
        .setup([&] { stack.clear(); })
        .run([&] {
            ScriptError error;
            const bool ret{EvalScript(stack, script, /*flags=*/0, BaseSignatureChecker(), SigVersion::BASE, nullptr, &error)};
            assert(ret && error == SCRIPT_ERR_OK);
        });
}

// Benchmark the cost of pushing and dropping small stack elements.
// The script pushes a 1-byte element (OP_1) and an empty element (OP_FALSE),
// dropping each right after pushing it. Each 4-byte cycle is repeated
// MAX_SCRIPT_SIZE / 4 times, filling the tapscript size limit exactly. Every
// OP_1/OP_FALSE materializes a fresh stack element, so this stresses the
// per-push allocation side of the stack element representation.
static void VerifyPushDropSmall(benchmark::Bench& bench)
{
    std::vector<ScriptStackElem> stack;
    CScript script;
    for (int i = 0; i < MAX_SCRIPT_SIZE / 4; ++i) {
        script << OP_1 << OP_DROP << OP_FALSE << OP_DROP;
    }
    assert(script.size() <= size_t{MAX_SCRIPT_SIZE});
    bench
        .setup([&] { stack.clear(); })
        .run([&] {
            ScriptError error;
            const bool ret{EvalScript(stack, script, /*flags=*/0, BaseSignatureChecker(), SigVersion::TAPSCRIPT, nullptr, &error)};
            assert(ret && error == SCRIPT_ERR_OK);
        });
}

// Benchmark the cost of duplicating and dropping a maximum-size stack element.
// The script pushes one large element and then repeats OP_DUP/OP_DROP as many
// times as fit in the tapscript size limit (MAX_SCRIPT_SIZE), keeping the stack
// size at 2.
static void VerifyDupDropLarge(benchmark::Bench& bench)
{
    std::vector<ScriptStackElem> stack;
    CScript script;
    script << std::vector<unsigned char>(MAX_SCRIPT_ELEMENT_SIZE, /*c=*/0xab);

    // Fill the rest up to the tapscript size limit with two-byte dup/drop pairs.
    size_t remaining_space = (size_t{MAX_SCRIPT_SIZE} - script.size());
    for (size_t i = 0; i < remaining_space / 2; ++i) {
        script << OP_DUP << OP_DROP;
    }
    assert(script.size() <= size_t{MAX_SCRIPT_SIZE});
    bench
        .setup([&] { stack.clear(); })
        .run([&] {
            ScriptError error;
            const bool ret{EvalScript(stack, script, /*flags=*/0, BaseSignatureChecker(), SigVersion::TAPSCRIPT, nullptr, &error)};
            assert(ret && error == SCRIPT_ERR_OK);
        });
}

// Benchmark the cost of pushing and dropping data elements of a fixed payload size.
// Each of the 100 pushes carries its bytes in the script (200 ops in total, under
// MAX_OPS_PER_SCRIPT), so unlike VerifyPushDropSmall every push materializes an
// element, and the payload size is swept across the range a script can push.
template <size_t N>
static void VerifyPushDropSized(benchmark::Bench& bench)
{
    std::vector<ScriptStackElem> stack;
    CScript script;
    constexpr int kPushes = (N > 100 ? 18 : 100); // keep the script under MAX_SCRIPT_SIZE
    for (int i = 0; i < kPushes; ++i) {
        script << std::vector<unsigned char>(N, uint8_t(0x41 + i));
    }
    for (int i = 0; i < kPushes; ++i) {
        script << OP_DROP;
    }
    bench.setup([&] { stack.clear(); })
        .run([&] {
            ScriptError error;
            const bool ret{EvalScript(stack, script, /*flags=*/0, BaseSignatureChecker(), SigVersion::BASE, nullptr, &error)};
            assert(ret && error == SCRIPT_ERR_OK);
        });
}

static void VerifyPushDropSized8(benchmark::Bench& bench) { VerifyPushDropSized<8>(bench); }
static void VerifyPushDropSized24(benchmark::Bench& bench) { VerifyPushDropSized<24>(bench); }
static void VerifyPushDropSized40(benchmark::Bench& bench) { VerifyPushDropSized<40>(bench); }
static void VerifyPushDropSized56(benchmark::Bench& bench) { VerifyPushDropSized<56>(bench); }
static void VerifyPushDropSized520(benchmark::Bench& bench) { VerifyPushDropSized<520>(bench); }

namespace {
// One dense hashing opcode cycle is `OP_3DUP + 3 * (HASH OP_DROP)`: 7 bytes, 3 hashes.
// The hashed element is placed on the stack by the bench, so it costs no script bytes.
// `OP_DUP OP_DUP` at the beginning of the script primes three copies, so tapscript allows
//   2 + 7 * cycles <= MAX_SCRIPT_SIZE     ->  1428 cycles, 9998 bytes, 4284 hashes
// and p2(w)sh allows
//   2 + 7 * cycles <= MAX_OPS_PER_SCRIPT  ->    28 cycles,  198 opcodes, 84 hashes
constexpr size_t TAPSCRIPT_HASH_CYCLES = 1428;
constexpr size_t WITNESS_V0_HASH_CYCLES = 28;

// [DUP DUP (3DUP HASH DROP HASH DROP HASH DROP)...] applied to the single element the setup
// puts on the stack: the element is hashed three times per cycle and the stack is left as found.
// Tapscript has no opcode budget, so this is the densest hashing a 10000-byte script can ask for.
void BenchDenseHashScript(benchmark::Bench& bench, opcodetype opcode, size_t cycles, SigVersion sigversion, size_t elem_size)
{
    const std::vector<unsigned char> vch(elem_size, 0xab);
    CScript script;
    script << OP_DUP << OP_DUP;
    for (size_t i = 0; i < cycles; ++i) {
        script << OP_3DUP;
        for (int j = 0; j < 3; ++j) {
            script << opcode << OP_DROP;
        }
    }

    std::vector<ScriptStackElem> stack;
    bench.unit("script")
        .setup([&] {
            stack.clear();
            stack.push_back(MakeStackElem(std::vector<unsigned char>(vch)));
        })
        .run([&] {
            ScriptError error;
            const bool ret{EvalScript(stack, script, /*flags=*/0, BaseSignatureChecker(), sigversion, nullptr, &error)};
            assert(ret && error == SCRIPT_ERR_OK);
        });
}
} // namespace

static void VerifyScriptHashLoopSha256(benchmark::Bench& bench)
{
    BenchDenseHashScript(bench, OP_SHA256, TAPSCRIPT_HASH_CYCLES, SigVersion::TAPSCRIPT, MAX_SCRIPT_ELEMENT_SIZE);
}

static void VerifyScriptHashLoopHash256(benchmark::Bench& bench)
{
    BenchDenseHashScript(bench, OP_HASH256, TAPSCRIPT_HASH_CYCLES, SigVersion::TAPSCRIPT, MAX_SCRIPT_ELEMENT_SIZE);
}

static void VerifyScriptHashLoopRipemd160(benchmark::Bench& bench)
{
    BenchDenseHashScript(bench, OP_RIPEMD160, TAPSCRIPT_HASH_CYCLES, SigVersion::TAPSCRIPT, MAX_SCRIPT_ELEMENT_SIZE);
}

static void VerifyScriptHashLoopSha1(benchmark::Bench& bench)
{
    BenchDenseHashScript(bench, OP_SHA1, TAPSCRIPT_HASH_CYCLES, SigVersion::TAPSCRIPT, MAX_SCRIPT_ELEMENT_SIZE);
}

static void VerifyScriptHashLoopHash160(benchmark::Bench& bench)
{
    BenchDenseHashScript(bench, OP_HASH160, TAPSCRIPT_HASH_CYCLES, SigVersion::TAPSCRIPT, MAX_SCRIPT_ELEMENT_SIZE);
}

static void VerifyScriptHashWitnessV0Sha256Looped(benchmark::Bench& bench)
{
    BenchDenseHashScript(bench, OP_SHA256, WITNESS_V0_HASH_CYCLES, SigVersion::WITNESS_V0, MAX_SCRIPT_ELEMENT_SIZE);
}

// The same dense loop on an element below the cache threshold: every hash is a
// cache miss but cheap to compute directly.
static void VerifyScriptHashSmall(benchmark::Bench& bench)
{
    BenchDenseHashScript(bench, OP_SHA256, TAPSCRIPT_HASH_CYCLES, SigVersion::TAPSCRIPT, 20);
}

// Distinct elements, each hashed exactly once, so no entry is ever created. This measures what the
// cache costs when it can never hit. Elements are placed on the stack by the bench, which keeps the
// reference count of each at one when its hash runs. Uses tapscript, because 1000 hashes is far over
// MAX_OPS_PER_SCRIPT from P2(W)SH, and 1000 is the most the stack limit allows, since the check is
// stack.size() + altstack.size() > MAX_STACK_SIZE.
static void VerifyScriptHashDistinctLarge(benchmark::Bench& bench)
{
    constexpr int NUM_ELEMENTS = 1000;
    CScript script;
    for (int i = 0; i < NUM_ELEMENTS; ++i) {
        script << OP_SHA256 << OP_DROP;
    }
    std::vector<ScriptStackElem> stack;
    bench.unit("script")
        .setup([&] {
            stack.clear();
            for (int i = 0; i < NUM_ELEMENTS; ++i) {
                std::vector<unsigned char> elem(MAX_SCRIPT_ELEMENT_SIZE, 0xab);
                elem[0] = static_cast<unsigned char>(i);
                elem[1] = static_cast<unsigned char>(i >> 8);
                stack.push_back(MakeStackElem(std::move(elem)));
            }
        })
        .run([&] {
            ScriptError error;
            const bool ret{EvalScript(stack, script, /*flags=*/0, BaseSignatureChecker(), SigVersion::TAPSCRIPT, nullptr, &error)};
            assert(ret && error == SCRIPT_ERR_OK);
            assert(stack.empty());
        });
}

BENCHMARK(VerifyScriptHashLoopSha256);
BENCHMARK(VerifyScriptHashLoopHash256);
BENCHMARK(VerifyScriptHashLoopRipemd160);
BENCHMARK(VerifyScriptHashLoopSha1);
BENCHMARK(VerifyScriptHashLoopHash160);
BENCHMARK(VerifyScriptHashWitnessV0Sha256Looped);
BENCHMARK(VerifyScriptHashSmall);
BENCHMARK(VerifyScriptHashDistinctLarge);
BENCHMARK(VerifyScriptP2WPKH);
BENCHMARK(VerifyScriptP2SH_P2WPKH);
BENCHMARK(VerifyScriptP2TR_KeyPath);
BENCHMARK(VerifyScriptP2TR_ScriptPath);
BENCHMARK(VerifyNestedIfScript);
BENCHMARK(VerifyPushDropSmall);
BENCHMARK(VerifyDupDropLarge);
BENCHMARK(VerifyPushDropSized8);
BENCHMARK(VerifyPushDropSized24);
BENCHMARK(VerifyPushDropSized40);
BENCHMARK(VerifyPushDropSized56);
BENCHMARK(VerifyPushDropSized520);
