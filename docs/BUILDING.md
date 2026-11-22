# Qt 5 userspace build baseline

This baseline builds the legacy Linux userspace programs without running them.
The kernel module remains a separate C/kbuild project. A successful userspace
build does not establish runtime correctness or make the firewall safe to deploy.

## Dependencies

- Linux, a C/C++ toolchain and POSIX threads.
- Qt 5.15 development files for Core, Gui, Widgets, Network and Sql, including
  moc and uic. Use the Qt 5 qmake executable explicitly: the system's default
  `qmake` may select Qt 6, whose GUI API is not yet supported here.
- CMake 3.20 or newer and Ninja for the ADS CMake build.
- Make and Qt 5 qmake for the three legacy qmake projects.

The SQLite Qt driver is needed to use the application's database at runtime;
it is not needed to link the programs. No dependencies are downloaded by these
build commands.

## Build without running the firewall

Start in the repository root. All output goes into a fresh temporary directory;
do not reuse the checked-in, machine-specific Makefiles.

```sh
set -eu
repo_root="$PWD"
build_root="$(mktemp -d /tmp/kohmar-build.XXXXXX)"

for compiler in g++ clang++; do
    cmake -S "$repo_root/ADS" -B "$build_root/cmake-$compiler" -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_CXX_COMPILER="$compiler" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    cmake --build "$build_root/cmake-$compiler" --parallel 2
done

for compiler in g++ clang++; do
    for component in ADS drvctl SOM; do
        case "$component" in
            ADS) project=ADS.pro ;;
            drvctl) project=ads_drvctl.pro ;;
            SOM) project=SOM.pro ;;
        esac
        build_dir="$build_root/qmake-$component-$compiler"
        mkdir -p "$build_dir"
        (
            cd "$build_dir" || exit 1
            qmake-qt5 "$repo_root/$component/$project" \
                "QMAKE_CXX=$compiler" "QMAKE_LINK=$compiler"
            make -j2
        )
    done
done
```

On distributions using a different Qt 5 executable name, substitute the command
whose `-v` output identifies Qt 5.15. The generated programs are `ADS`,
`ads_drvctl` and `SOM` in their respective build directories. These commands
do not execute any of them, install anything, load a module or alter firewall
state. In particular, do not run `ads_drvctl start` as a build check.

## Verified scope

The baseline audit and repair use x86_64 Linux, GCC 14.3.1, Clang 19.1.7 with
libstdc++, Qt 5.15.17, CMake 3.30.8, Ninja and GNU Make. These are observed
versions, not a supported-platform matrix or a recommendation to retain the
audit host's obsolete Fedora 41 installation. Repeat the matrix on a supported
Linux release before pinning a CI image. ARM64 and i386 builds and signal
handling at runtime still need separate verification.

Both build systems request C++23. The ADS CMake target deliberately retains
GNU extensions because `PST/pst_builder.cpp` contains a variable-length array.
The qmake builds also rely on the compilers accepting that extension. Do not
claim strict ISO C++23 conformance or add a global `-Werror` gate until the
legacy warnings have been characterized. No detection algorithm is rewritten
as part of this baseline repair.

The daemon's signal context selection uses the x86_64 instruction-pointer
register for the x86_64 build. The existing AArch64 and i386 register accesses
are retained under explicit architecture guards; other architectures fail
compilation rather than assuming that every 64-bit CPU has ARM registers.
The legacy signal handler still performs operations that are not
async-signal-safe; compiling it does not validate its crash-reporting behavior.

## Tests, coverage and known gaps

There is no automated test suite, CTest registration or project-wide line/branch
coverage baseline in this revision. This build repair does not introduce them;
the next infrastructure change should add characterization tests and publish
both coverage metrics before setting numerical thresholds. The initial
configure/compile failures are build-regression evidence, not functional TDD
tests. No application startup, privileged network check or kernel runtime test
is part of this baseline.

Existing warnings include deprecated Qt APIs, deprecated standard-library
adapters, a C++ variable-length array, uninitialized-pointer diagnostics and
tautological range checks. They remain visible; warning suppression is not a
build fix. Known packet-parsing, memory, thread-lifetime and kernel/control-plane
defects require independent tests and fixes before deployment. Qt 6 migration,
kernel build repair, sanitizers and isolated-VM integration are separate work.
