// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_STACK_ELEM_H
#define BITCOIN_SCRIPT_STACK_ELEM_H

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <utility>
#include <vector>

/** A pointer to a heap object which counts its own references.
 *
 *  The pointee maintains its reference count inside itself, so no control block is allocated. The count is
 *  not synchronized: a RefCountedPtr, and the object it points to, must never be used from more than one
 *  thread.
 *
 *  T must provide, at least:
 *    - `void AddRef() const`: increment the reference count,
 *    - `void Release() const`: decrement it, and destroy & deallocate the object when it reaches zero,
 *    - `use_count() const`: the number of references, for diagnostics and tests.
 *
 *  A raw pointer handed to this class must already have its count incremented for the reference being
 *  adopted.
 */
template <typename T>
class RefCountedPtr
{
    const T* m_ptr{nullptr};

public:
    RefCountedPtr() noexcept = default;
    explicit RefCountedPtr(const T* ptr) noexcept : m_ptr{ptr} {}

    RefCountedPtr(const RefCountedPtr& ref) noexcept : m_ptr{ref.m_ptr}
    {
        if (m_ptr) m_ptr->AddRef();
    }
    RefCountedPtr(RefCountedPtr&& ref) noexcept : m_ptr{std::exchange(ref.m_ptr, nullptr)} {}

    RefCountedPtr& operator=(const RefCountedPtr& ref) noexcept
    {
        // Add the new reference before dropping the old one, so that self-assignment is safe.
        if (ref.m_ptr) ref.m_ptr->AddRef();
        if (m_ptr) m_ptr->Release();
        m_ptr = ref.m_ptr;
        return *this;
    }
    RefCountedPtr& operator=(RefCountedPtr&& ref) noexcept
    {
        if (this == std::addressof(ref)) return *this;
        if (m_ptr) m_ptr->Release();
        m_ptr = std::exchange(ref.m_ptr, nullptr);
        return *this;
    }

    ~RefCountedPtr()
    {
        if (m_ptr) m_ptr->Release();
    }

    /** Drop the held reference, emptying the pointer. */
    void reset() noexcept
    {
        *this = RefCountedPtr{};
    }

    const T* get() const noexcept { return m_ptr; }
    const T& operator*() const noexcept
    {
        assert(m_ptr);
        return *m_ptr;
    }
    const T* operator->() const noexcept
    {
        assert(m_ptr);
        return m_ptr;
    }
    explicit operator bool() const noexcept { return m_ptr != nullptr; }

    /** The number of RefCountedPtrs sharing the object, 0 for an empty pointer. */
    size_t use_count() const noexcept { return m_ptr ? m_ptr->use_count() : 0; }

    /** Pointer identity, as for std::shared_ptr. */
    template <typename U>
    friend bool operator==(const RefCountedPtr& a, const RefCountedPtr<U>& b) noexcept
    {
        return a.m_ptr == b.m_ptr;
    }
    template <typename U>
    friend bool operator<(const RefCountedPtr& a, const RefCountedPtr<U>& b) noexcept
    {
        return a.m_ptr < b.m_ptr;
    }
};

/** An immutable byte string, stored in a single heap allocation together with the reference count of the
 *  ScriptStackElem pointers which refer to it:
 *
 *      [ refcount: uint32_t ][ size: uint32_t ][ the bytes ... ]
 *
 *  The reference count is not atomic: script evaluation is single-threaded and an interpreter stack is
 *  never shared between threads, so a ScriptStackElem must never be copied between threads.
 *
 *  Elements are created by MakeStackElem() only, and are immutable afterwards.
 */
class ScriptStackElemData
{
    /** The reference count and the length, in the allocation itself: the bytes of an element start right
     *  after them, so that count, length and contents are created, found and freed by one allocation. The
     *  count is mutable because AddRef() and Release() are const: elements are held by const pointers.
     */
    struct Header {
        mutable uint32_t m_refcount;
        uint32_t m_size;
    };
    static_assert(sizeof(Header) == 8);

    //! Bytes an element of length size occupies in memory: the header plus the bytes.
    static constexpr size_t BlockSize(size_t size) noexcept { return sizeof(Header) + size; }

    Header m_header;

    ScriptStackElemData(std::span<const uint8_t> bytes) noexcept
        : m_header{1, static_cast<uint32_t>(bytes.size())}
    {
        std::copy(bytes.begin(), bytes.end(), const_cast<uint8_t*>(data()));
    }
    ~ScriptStackElemData() = default;

    // Elements exist only as blocks created by Create(), shared by ScriptStackElem pointers.
    ScriptStackElemData(const ScriptStackElemData&) = delete;
    ScriptStackElemData& operator=(const ScriptStackElemData&) = delete;
    ScriptStackElemData(ScriptStackElemData&&) = delete;
    ScriptStackElemData& operator=(ScriptStackElemData&&) = delete;

public:
    /** Allocate an element with a copy of bytes and a reference count of one. Throws std::bad_alloc. */
    static const ScriptStackElemData* Create(std::span<const uint8_t> bytes);

    /** Add a reference. */
    void AddRef() const noexcept
    {
        assert(m_header.m_refcount > 0 && m_header.m_refcount < std::numeric_limits<uint32_t>::max());
        ++m_header.m_refcount;
    }
    /** Drop a reference, destroying and deallocating the element when it was the last one. */
    void Release() const noexcept;

    size_t size() const noexcept { return m_header.m_size; }
    bool empty() const noexcept { return m_header.m_size == 0; }
    const uint8_t* data() const noexcept { return reinterpret_cast<const uint8_t*>(this) + sizeof(Header); }
    const uint8_t* begin() const noexcept { return data(); }
    const uint8_t* end() const noexcept { return data() + m_header.m_size; }
    std::span<const uint8_t> bytes() const noexcept { return {data(), m_header.m_size}; }
    uint32_t use_count() const noexcept { return m_header.m_refcount; }
};

/** An element of the script interpreter's stack: a reference-counted pointer to an immutable byte string,
 *  so that duplicating or reordering a stack item copies a pointer, never the element's contents. */
using ScriptStackElem = RefCountedPtr<ScriptStackElemData>;
// A stack slot is one pointer, with no control block.
static_assert(sizeof(ScriptStackElem) == sizeof(void*));

/** Make a stack element with a copy of bytes. */
ScriptStackElem MakeStackElem(std::span<const uint8_t> bytes);
/** Make a stack element with a copy of the contents of v. */
ScriptStackElem MakeStackElem(std::vector<unsigned char>&& v);

#endif // BITCOIN_SCRIPT_STACK_ELEM_H
