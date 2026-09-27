# Building kohmar-firewall

## Requirements

- CMake 3.16 or newer
- C11 compiler
- C++17 compiler
- Qt 5 or Qt 6 with Core, Gui, Widgets, Network and Sql
- Linux kernel headers matching the running kernel
- SQLite Qt plugin

## Userspace build

```shell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

Executables:

```shell
build/apps/ads/ads
build/apps/drvctl/ads_drvctl
```

Kernel module:

```shell
cmake --build build --target ads_netfilter_module
```

Alternatively:

```shell
make -C kernel/ads_netfilter
```

The kernel module requires the headers for the currently running kernel.

Tests:

```shell
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```