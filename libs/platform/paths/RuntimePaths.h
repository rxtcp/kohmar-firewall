#pragma once

#include <filesystem>
#include <string_view>

namespace firewall {

class RuntimePaths final {
 public:
  using Path = std::filesystem::path;

  [[nodiscard]] static RuntimePaths fromEnvironment();

  RuntimePaths(Path configDirectory, Path stateDirectory, Path runtimeDirectory,
               Path kernelModule);

  [[nodiscard]] const Path& configDirectory() const noexcept;
  [[nodiscard]] const Path& stateDirectory() const noexcept;
  [[nodiscard]] const Path& runtimeDirectory() const noexcept;
  [[nodiscard]] const Path& kernelModule() const noexcept;

  [[nodiscard]] Path adsSettings() const;
  [[nodiscard]] Path readerConfig() const;
  [[nodiscard]] Path moduleConfig() const;

  [[nodiscard]] Path databaseDirectory() const;
  [[nodiscard]] Path firewallDatabase() const;

  [[nodiscard]] Path samplesDirectory() const;
  [[nodiscard]] Path sample(std::string_view fileName) const;

  [[nodiscard]] Path pidFile(std::string_view processName) const;
  [[nodiscard]] Path socketFile(std::string_view socketName) const;

 private:
  Path configDirectory_;
  Path stateDirectory_;
  Path runtimeDirectory_;
  Path kernelModule_;
};

}  // namespace firewall