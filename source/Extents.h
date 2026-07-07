#pragma once

template<typename T>
class Extents {
public:
    using ValueType = T;

    constexpr Extents() : m_start(0), m_end(0) {}
    constexpr Extents(T start, T size) : m_start(start), m_end(start + size) {}

    [[nodiscard]] constexpr T GetStart() const noexcept { return m_start; }
    [[nodiscard]] constexpr T GetEnd()   const noexcept { return m_end; }
    [[nodiscard]] constexpr T GetSize()  const noexcept { return m_end - m_start; }

    [[nodiscard]] constexpr bool Contains(T val) const noexcept {
        return val >= m_start && val < m_end;
    }

    constexpr void Extend(ValueType v)  noexcept { m_end += v; }
    constexpr void Forward(ValueType v) noexcept { m_start += v; }

    [[nodiscard]] constexpr Extents<T> Extended(T v) const noexcept {
        Extents<T> ext = *this;
        ext.m_end += v;
        return ext;
    }

    [[nodiscard]] constexpr Extents<T> Forwarded(T v) const noexcept {
        Extents<T> ext = *this;
        ext.m_start += v;
        return ext;
    }
protected:
    T m_start, m_end;
}; // class Extents
