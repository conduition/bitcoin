// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/stack_elem.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <vector>

const ScriptStackElemData* ScriptStackElemData::Create(std::span<const uint8_t> bytes)
{
    assert(bytes.size() <= std::numeric_limits<uint32_t>::max());
    // Plain new, matched by the plain delete in Release(): the default alignment is 16 on the platforms we
    // build for, which is more than this type needs, and asking for it explicitly takes a slower path.
    void* mem = ::operator new(BlockSize(bytes.size()));
    return new (mem) ScriptStackElemData{bytes};
}

void ScriptStackElemData::Release() const noexcept
{
    assert(m_header.m_refcount > 0);
    if (m_header.m_refcount > 1) {
        --m_header.m_refcount;
        return;
    }
    this->~ScriptStackElemData();
    ::operator delete(const_cast<ScriptStackElemData*>(this));
}

ScriptStackElem MakeStackElem(std::span<const uint8_t> bytes)
{
    return ScriptStackElem{ScriptStackElemData::Create(bytes)};
}

ScriptStackElem MakeStackElem(std::vector<unsigned char>&& v)
{
    return MakeStackElem(std::span<const uint8_t>{v.data(), v.size()});
}
