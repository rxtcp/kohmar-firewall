#pragma once

#include <string_view>

namespace firewall::system_paths {

inline constexpr std::string_view setupDevice{"/dev/ads_drv_setup"};

inline constexpr std::string_view mmapDevice{"/dev/ads_sniff_mmap"};

inline constexpr std::string_view procDevices{"/proc/devices"};

inline constexpr std::string_view nullDevice{"/dev/null"};

}  // namespace firewall::system_paths