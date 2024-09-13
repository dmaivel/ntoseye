#pragma once

#include <memory>
#include <fstream>
#include <algorithm>
#include <vector>

#include "mem.hpp"

namespace pdb {
    constexpr int max_download_attempts = 2;

    enum class process_priv {
        kernel,
        user
    };

    struct symbol {
        enum class sym_type {
            data,
            function
        };

        std::string name;
        uint64_t offset;
        sym_type type;
    };

    struct metadata {
        std::string filename;
        std::string id; // guid + age
        std::string url;

        // if anything is empty, consider the pdb invalid
        inline bool valid()
        {
            return !filename.empty() && !id.empty() && !url.empty();
        }

        static inline std::string read_id_from_disk(const std::string &path)
        {
            std::ifstream file(path);
            std::string result;
            std::getline(file, result);
            return result;
        }

        inline void write_id_to_disk(const std::string &path)
        {
            std::ofstream file(path);
            file << id;
        }
    };

    void load(mem::process &process, process_priv priv);
    std::optional<pdb::symbol> get(const std::string &str);
    std::vector<pdb::symbol> get_all();
}