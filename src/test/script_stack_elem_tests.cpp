// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/stack_elem.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

/** A type which counts live instances, to observe when the last reference to a RefCountedPtr object dies. */
class Counted
{
    mutable uint32_t m_refcount{1};
    inline static size_t s_live{0};

public:
    Counted() { ++s_live; }
    ~Counted() { --s_live; }

    void AddRef() const noexcept { ++m_refcount; }
    void Release() const noexcept
    {
        if (--m_refcount == 0) delete const_cast<Counted*>(this);
    }
    uint32_t use_count() const noexcept { return m_refcount; }

    static size_t Live() { return s_live; }
};

using CountedPtr = RefCountedPtr<Counted>;

/** Make an object with a reference count of one, as RefCountedPtr expects from a factory. */
CountedPtr MakeCounted() { return CountedPtr{new Counted{}}; }

std::vector<uint8_t> BytesOf(const ScriptStackElem& elem) { return {elem->begin(), elem->end()}; }

std::vector<uint8_t> MakeBytes(size_t n)
{
    std::vector<uint8_t> bytes(n);
    for (size_t i = 0; i < n; ++i)
        bytes[i] = uint8_t(i % 251);
    return bytes;
}

} // namespace

BOOST_AUTO_TEST_CASE(refcounted_ptr_tests)
{
    BOOST_CHECK_EQUAL(Counted::Live(), 0);

    // The object is created for the first reference, and destroyed with the last one.
    {
        CountedPtr one = MakeCounted();
        BOOST_CHECK_EQUAL(Counted::Live(), 1);
        BOOST_CHECK_EQUAL(one.use_count(), 1);
        BOOST_CHECK(one.get() != nullptr);
        BOOST_CHECK(bool(one));
    }
    BOOST_CHECK_EQUAL(Counted::Live(), 0);

    // Copies share one object; the count is the number of live pointers.
    {
        CountedPtr a = MakeCounted();
        {
            CountedPtr b{a};
            CountedPtr c = b;
            BOOST_CHECK_EQUAL(Counted::Live(), 1);
            BOOST_CHECK_EQUAL(a.use_count(), 3);
            BOOST_CHECK_EQUAL(b.use_count(), 3);
            BOOST_CHECK(a.get() == c.get());

            c = a; // self-assignment through another pointer: nothing changes
            BOOST_CHECK_EQUAL(a.use_count(), 3);
            a = a; // self-assignment
            BOOST_CHECK_EQUAL(a.use_count(), 3);
        }
        BOOST_CHECK_EQUAL(a.use_count(), 1);
        BOOST_CHECK_EQUAL(Counted::Live(), 1);
    }
    BOOST_CHECK_EQUAL(Counted::Live(), 0);

    // A moved-from pointer is empty and holds no reference.
    {
        CountedPtr a = MakeCounted();
        {
            CountedPtr b{std::move(a)};
            BOOST_CHECK(a.get() == nullptr);
            BOOST_CHECK(!a);
            BOOST_CHECK_EQUAL(a.use_count(), 0);
            BOOST_CHECK_EQUAL(b.use_count(), 1);
            BOOST_CHECK_EQUAL(Counted::Live(), 1);

            CountedPtr c = MakeCounted();
            BOOST_CHECK_EQUAL(Counted::Live(), 2);
            c = std::move(b); // the object c referred to is released here
            BOOST_CHECK_EQUAL(Counted::Live(), 1);
            BOOST_CHECK_EQUAL(c.use_count(), 1);
            CountedPtr& aliased = c;
            c = std::move(aliased); // self-move-assignment keeps the object alive
            BOOST_CHECK_EQUAL(Counted::Live(), 1);
            BOOST_CHECK_EQUAL(c.use_count(), 1);
            BOOST_CHECK(c.get() != nullptr);
            c.reset();
            BOOST_CHECK_EQUAL(Counted::Live(), 0);
        }
        BOOST_CHECK_EQUAL(Counted::Live(), 0);
    }

    // Containers move pointers around without changing the ref count.
    {
        CountedPtr a = MakeCounted();
        std::vector<CountedPtr> v;
        for (int i = 0; i < 100; ++i)
            v.push_back(a);
        BOOST_CHECK_EQUAL(a.use_count(), 101);
        std::vector<CountedPtr> w = std::move(v);
        BOOST_CHECK_EQUAL(a.use_count(), 101);
        BOOST_CHECK_EQUAL(Counted::Live(), 1);
        v = std::move(w);
        BOOST_CHECK_EQUAL(a.use_count(), 101);
        v.pop_back();
        BOOST_CHECK_EQUAL(a.use_count(), 100);
    }
    BOOST_CHECK_EQUAL(Counted::Live(), 0);
}

BOOST_AUTO_TEST_CASE(stack_elem_tests)
{
    // Elements of every interesting length are immutable.
    for (size_t n : {size_t{0}, size_t{1}, size_t{8}, size_t{32}, size_t{33}, size_t{520}}) {
        const std::vector<uint8_t> bytes = MakeBytes(n);
        ScriptStackElem elem = MakeStackElem(std::span<const uint8_t>{bytes});
        BOOST_REQUIRE_EQUAL(elem->size(), n);
        BOOST_CHECK_EQUAL(elem->empty(), n == 0);
        BOOST_CHECK(elem->data() != nullptr);
        BOOST_CHECK_EQUAL(elem.use_count(), 1);
        BOOST_CHECK(BytesOf(elem) == bytes);

        // Duplicating the pointer shares the bytes; the contents and the identity are the same.
        {
            ScriptStackElem dup{elem};
            BOOST_CHECK_EQUAL(elem.use_count(), 2);
            BOOST_CHECK(dup.get() == elem.get());
            BOOST_CHECK(BytesOf(dup) == bytes);
            {
                ScriptStackElem moved = std::move(dup);
                BOOST_CHECK_EQUAL(elem.use_count(), 2);
                BOOST_CHECK_EQUAL(dup.use_count(), 0);
                BOOST_CHECK(BytesOf(moved) == bytes);
            }
            BOOST_CHECK_EQUAL(elem.use_count(), 1);
        }
        BOOST_CHECK_EQUAL(elem.use_count(), 1);
    }

    // The interpreter pushes OP_1NEGATE and OP_1..OP_16 from a table of precomputed CScriptNum encodings.
    // Check the table against what CScriptNum itself produces, and that an OP_0 push shares the empty element.
    {
        const std::vector<opcodetype> opcodes{
            OP_1NEGATE, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
            OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16};
        for (const opcodetype opcode : opcodes) {
            const int64_t n = (opcode == OP_1NEGATE) ? -1 : int64_t(opcode) - int64_t(OP_1) + 1;
            std::vector<ScriptStackElem> stack;
            ScriptError err;
            BOOST_CHECK(EvalScript(stack, CScript() << opcode, SCRIPT_VERIFY_NONE, BaseSignatureChecker(),
                                   SigVersion::BASE, nullptr, &err));
            BOOST_REQUIRE_EQUAL(stack.size(), 1);
            BOOST_CHECK_EQUAL(stack[0]->size(), 1);
            BOOST_CHECK(BytesOf(stack[0]) == CScriptNum(n).getvch());
        }

        std::vector<ScriptStackElem> stack;
        ScriptError err;
        BOOST_CHECK(EvalScript(stack, CScript() << OP_0 << OP_0 << OP_1NEGATE, SCRIPT_VERIFY_NONE,
                               BaseSignatureChecker(), SigVersion::BASE, nullptr, &err));
        BOOST_REQUIRE_EQUAL(stack.size(), 3);
        BOOST_CHECK(stack[0].get() == stack[1].get()); // the empty element is shared
        BOOST_CHECK(stack[0].get() != stack[2].get());
        BOOST_CHECK(stack[0]->empty() && stack[2]->size() == 1);
    }

    // The from-vector constructor copies the bytes, and is the only owner of the element.
    {
        std::vector<unsigned char> v = MakeBytes(600);
        ScriptStackElem elem = MakeStackElem(std::move(v));
        BOOST_CHECK_EQUAL(elem->size(), 600);
        BOOST_CHECK_EQUAL(elem.use_count(), 1);
        BOOST_CHECK(BytesOf(elem) == std::vector<uint8_t>(MakeBytes(600)));
    }

    // Thousands of short-lived elements created, duplicated, reordered and dropped. Every allocation is
    // released again - LeakSanitizer checks this in an ASan build.
    {
        size_t sum = 0;
        for (int i = 0; i < 1000; ++i) {
            std::vector<ScriptStackElem> stack;
            stack.push_back(MakeStackElem(std::span<const uint8_t>{}));
            stack.push_back(MakeStackElem(MakeBytes(size_t(i) % 100 + 1)));
            ScriptStackElem copy{stack[0]};
            stack.insert(stack.end() - 1, std::move(copy));
            stack.pop_back();
            BOOST_CHECK_EQUAL(stack[0].use_count(), 2); // two slots and no test handle: the copy was moved
            sum += stack.size();
        }
        BOOST_CHECK_EQUAL(sum, 2000);
    }
}
