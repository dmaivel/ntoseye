#pragma once

#include <string>

namespace curl {
    bool initialize();
    bool attempt_file_download(const std::string &dst, const std::string &url);
}