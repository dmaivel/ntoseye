#pragma once

#include <string>

namespace config {
    inline std::string get_storage_directory()
    {
        constexpr auto get_user_home_directory = []() {
            auto sudo_user = std::getenv("SUDO_USER");
            if (sudo_user != nullptr) {
                std::string home = "/home/";
                home += sudo_user;
                return home;
            }

            auto home = std::getenv("HOME");
            return (home != nullptr) ? home : std::string();
        };

        std::string config_directory;

        auto config_directory_env = std::getenv("XDG_CONFIG_HOME");
        if (config_directory_env == nullptr) {
            config_directory = get_user_home_directory();
            config_directory += "/.config";
        }
        else {
            config_directory = config_directory_env;
        }

        return config_directory + "/ntoseye";
    }
}