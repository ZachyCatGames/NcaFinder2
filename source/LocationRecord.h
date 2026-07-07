#pragma once
#include <list>
#include "Common.h"

template<typename T, typename Tag>
class LocationExtents {
public:
    using ValueType = T;

    constexpr LocationExtents() :
        m_imgOffset(0),
        m_sectOffset(0),
        m_size(0) {}

    constexpr LocationExtents(ValueType imgOffs, ValueType sectOffs, ValueType size) :
        m_imgOffset(imgOffs),
        m_sectOffset(sectOffs),
        m_size(size) {}
    
    [[nodiscard]] constexpr ValueType GetImageStart() const noexcept { return m_imgOffset; }
    [[nodiscard]] constexpr ValueType GetImageEnd()   const noexcept { return m_imgOffset + m_size; }

    [[nodiscard]] constexpr ValueType GetSectionStart() const noexcept { return m_sectOffset; }
    [[nodiscard]] constexpr ValueType GetSectionEnd()   const noexcept { return m_sectOffset + m_size; }
    
    [[nodiscard]] constexpr ValueType GetSize() const noexcept { return m_size; }
    
    constexpr void Extend(ValueType by) noexcept {
        m_size += by;
    }

    constexpr void Forward(ValueType by) noexcept {
        m_imgOffset += by;
        m_sectOffset += by;
    }

    [[nodiscard]] constexpr auto Extended(ValueType by) const noexcept {
        auto ext = *this;
        ext.m_size += by;
        return ext;
    }

    [[nodiscard]] constexpr auto Forwarded(ValueType by) const noexcept {
        auto ext = *this;
        ext.m_imgOffset += by;
        ext.m_sectOffset += by;
        return ext;
    }
private:
    ValueType m_imgOffset;
    ValueType m_sectOffset;
    ValueType m_size;
}; // class RecoveredRecord

template<typename T, typename Tag>
constexpr auto operator<=>(const LocationExtents<T, Tag>& lhs, const LocationExtents<T, Tag>& rhs) {
    return lhs.GetSectionStart() <=> rhs.GetSectionStart();
}

namespace detail {

struct RecoveredTag {};

} // namespace detail

using RecoveredRecord = LocationExtents<u64, detail::RecoveredTag>;

template<typename T, typename Tag>
class LocationExtentsList : public std::list<LocationExtents<T, Tag>> {
public:
    void coalesce() {
        auto cur = this->begin();
        auto next = std::next(cur);
        while (next != this->end()) {
            while (true) {
                if (cur->GetSectionStart() + cur->GetSize() != next->GetSectionStart()) {
                    break;
                }
                cur->Extend(next->GetSize());
                next = this->erase(next);
            }
            ++cur;
            ++next;
        }
    }
}; // class LocationExtentsList

using RecoveredList = LocationExtentsList<u64, detail::RecoveredTag>;
