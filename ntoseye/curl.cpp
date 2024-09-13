#include "curl.hpp"
#include "cmd.hpp"
#include "config.hpp"
#include "util.hpp"
#include "log.hpp"

#include <curl/curl.h>

CURL *curl_state;

bool curl::initialize()
{
    curl_state = curl_easy_init();
    if (!curl_state)
        out::warn("failed to initialize libcurl, note downloads will not work\n");
    return curl_state;
}

bool curl::attempt_file_download(const std::string &dst, const std::string &url)
{
    auto file = std::fopen(dst.c_str(), "w");
    if (!file || dst.empty())
        return false;

    curl_easy_setopt(curl_state, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_state, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(curl_state, CURLOPT_FOLLOWLOCATION, 1L);

    // std::print("Downloading from '{}'... ", url);
    // std::fflush(stdout);

    auto res = curl_easy_perform(curl_state);
    bool status = res == CURLE_OK;

    // std::println("{}", status ? "done" : "error");

    std::fclose(file);

    return status;
}