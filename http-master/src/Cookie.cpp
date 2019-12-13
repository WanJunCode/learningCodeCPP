/*
 * Copyright (c) 2014 Matt Fichman
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, APEXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "http/Common.hpp"
#include "http/Cookies.hpp"
#include "http/Parse.hpp"

namespace http {

// 获得 键名称
ParseResult<std::string> parseName(char const* str) {
    return parseUntil(str, [](char ch) { return isspace(ch) || ch == '='; });
}

// 获取值
ParseResult<std::string> parseValue(char const* str) {
    return parseUntil(str, [](char ch) { return ch == ';' || ch == '='; });
}

// 跳过开始的 空格并返回，如果 str 为 NULL 则返回 空的 ParseResult
ParseResult<std::string> parseSeparator(char const* str) {
    if (*str) {
        // str != NULL
        assert(*str==';'||*str=='='); 
        return parseWhitespace(str+1);
    } else {
        // str == NULL
        auto result = ParseResult<std::string>{};
        result.ch = str;
        return result;
    }
}

Cookie parseCookie(char const* str) {
    // 获得键名称
    auto name = parseName(str);
    // 跳过空格
    auto ch = parseSeparator(name.ch).ch;
    // 获得值
    auto value = parseValue(ch);
    // 跳过空格
    ch = parseSeparator(value.ch).ch;

    // 创建 Cookie 对象
    auto cookie = Cookie();
    cookie.nameIs(name.value);
    cookie.valueIs(value.value);

    // 获得 cookie 后续的属性
    while (*ch) {
        auto flag = parseValue(ch);
        if (flag.value == "Path") {
            ch = parseSeparator(flag.ch).ch;
            flag = parseValue(ch);
            cookie.pathIs(flag.value);
        } else if (flag.value == "HttpOnly") {
            cookie.httpOnlyIs(true);
        } else if (flag.value == "Secure") {
            cookie.secureIs(true);
        }
        ch = parseSeparator(flag.ch).ch;
    }
    return cookie;
}

// 构造函数
Cookie::Cookie(std::string const& text) {
    *this = parseCookie(text.c_str());
}

Cookie const Cookies::cookie(std::string const& name) const {
    // 在 cookie map 中查找
    auto i = cookie_.find(name);
    // 没有找到则返回一个空值 cookie
    return (i == cookie_.end()) ? Cookie() : i->second;
}

// 设置新的 cookie， 其中的 cookie.name 作为键
void Cookies::cookieIs(Cookie const& cookie) {
    cookie_[cookie.name()] = cookie;
}

}

