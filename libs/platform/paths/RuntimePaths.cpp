#include "platform/paths/RuntimePaths.h"

#include <cstdlib>
#include <string>
#include <utility>

#include "firewall/install_paths.h"

namespace firewall {
namespace {

RuntimePaths::Path pathFromEnvironment(const char* variableName,
                                       const char* defaultValue) {
  if (const char* value = std::getenv(variableName);
      value != nullptr && value[0] != '\0') {
    return value;
  }

  return defaultValue;
}

}  // namespace

RuntimePaths RuntimePaths::fromEnvironment() {
  return RuntimePaths{
      pathFromEnvironment("KOHMAR_CONFIG_DIR", KOHMAR_DEFAULT_CONFIG_DIR),
      pathFromEnvironment("KOHMAR_STATE_DIR", KOHMAR_DEFAULT_STATE_DIR),
      pathFromEnvironment("KOHMAR_RUNTIME_DIR", KOHMAR_DEFAULT_RUNTIME_DIR),
      pathFromEnvironment("KOHMAR_MODULE_FILE", KOHMAR_DEFAULT_MODULE_FILE)};
}

RuntimePaths::RuntimePaths(Path configDirectory, Path stateDirectory,
                           Path runtimeDirectory, Path kernelModule)
    : configDirectory_(std::move(configDirectory)),
      stateDirectory_(std::move(stateDirectory)),
      runtimeDirectory_(std::move(runtimeDirectory)),
      kernelModule_(std::move(kernelModule)) {}

const RuntimePaths::Path& RuntimePaths::configDirectory() const noexcept {
  return configDirectory_;
}

const RuntimePaths::Path& RuntimePaths::stateDirectory() const noexcept {
  return stateDirectory_;
}

const RuntimePaths::Path& RuntimePaths::runtimeDirectory() const noexcept {
  return runtimeDirectory_;
}

const RuntimePaths::Path& RuntimePaths::kernelModule() const noexcept {
  return kernelModule_;
}

RuntimePaths::Path RuntimePaths::adsSettings() const {
  return configDirectory_ / "ads.settings";
}

RuntimePaths::Path RuntimePaths::readerConfig() const {
  return configDirectory_ / "readerd.conf";
}

RuntimePaths::Path RuntimePaths::moduleConfig() const {
  return configDirectory_ / "module.conf";
}

RuntimePaths::Path RuntimePaths::databaseDirectory() const {
  return stateDirectory_ / "db";
}

RuntimePaths::Path RuntimePaths::firewallDatabase() const {
  return databaseDirectory() / "db_firewall.sqlite";
}

RuntimePaths::Path RuntimePaths::samplesDirectory() const {
  return stateDirectory_ / "samples";
}

RuntimePaths::Path RuntimePaths::sample(std::string_view fileName) const {
  return samplesDirectory() / fileName;
}

RuntimePaths::Path RuntimePaths::pidFile(std::string_view processName) const {
  return runtimeDirectory_ / (std::string{processName} + ".pid");
}

RuntimePaths::Path RuntimePaths::socketFile(std::string_view socketName) const {
  return runtimeDirectory_ / ("signal_" + std::string{socketName});
}

}  // namespace firewall