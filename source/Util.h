#pragma once

template<typename T>
constexpr T AlignUp(T val, T align) {
    T tmp = (val + align - 1);
    return tmp - tmp % align;
}
