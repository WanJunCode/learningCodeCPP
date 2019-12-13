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

#pragma once

#include "http/Common.hpp"
#include "http/Headers.hpp"
#include "http/Uri.hpp"

namespace http {

class Request {
public:
    enum Method { GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT };

    Method method() const { return method_; }
    Uri const& uri() const { return uri_; }
    std::string const& path() const { return uri_.path(); }
    std::string const& data() const { return data_; }
    std::string const header(std::string const& name) const;
    Headers const& headers() const { return headers_; }

    void methodIs(Method method);
    void uriIs(Uri const& path);
    void dataIs(std::string const& data);
    void headerIs(std::string const& name, std::string const& value);

private:
    Method method_ = GET;       // 设置默认方法为 GET
    Uri uri_;
    std::string data_;
    Headers headers_;
};

}
