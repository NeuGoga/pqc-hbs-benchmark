# pqc-hbs-benchmark
C++ Benchmarking tool for NIST Post-Quantum Hash-Based Signatures using the Open Quantum Safe library.

## Setting up

You must have the **Open Quantum Safe (liboqs)** library installed. Because this benchmark tests stateful schemes, **you must compile liboqs from source** with specific flags enabled.

## Security Warning

**DO NOT USE THE CUSTOM IMPLEMENTATION (`libs/hbs`) IN PRODUCTION**

The custom SPHINCS+ implementation included in this project (`MY_SPHINCS-*`) is an **educational reference implementation**
* It uses a scalar implementation of Keccak (slower than AVX2).
* It is not safe.

It is intended solely for benchmarking. It **does** match the official SPHINCS+ SHAKE-simple reference on known-answer tests (see `tests/`).

---

### 1. Installing liboqs (Windows)

**Requirements:**
*   Visual Studio 2022 (with C++ Desktop Development workload)
*   CMake
*   Git

**Steps**
1. Open the **Developer Command Propmt for VS 2022**.
2. Clone the library:
    ```cmd
    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    ```
3. Create build directory:
    ```cmd
    mkdir build
    cd build
    ```
4. **Configure with required flags:**
    ```
    cmake .. -G "Visual Studio 17 2022" -A x64 -DBUILD_SHARED_LIBS=ON -DOQS_ENABLE_SIG_STFL_XMSS=ON -DOQS_ENABLE_SIG_STFL_LMS=ON -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON
    ```
5. Build the library in Release mode:
    ```cmd
    cmake --build . --config Release
    ```
6. (Optional) Install globally (requires Admin prompt):
    ```cmd
    cmake --install . --config Release
    ```
    *If you do not install globally, note the path to this `liboqs` folder.*

### 2. Installing liboqs (Linux):

**Requirements:**
* GCC/G++, Cmake, Git, OpenSSL (`sudo apt install build-essential cmake libssl-dev git`)

**Steps**
1. Clone and prepare directory:
    ```bash
    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir build && cd build
    ```
2. **Configure with require flags:**
    ```bash
    cmake .. -DBUILD_SHARED_LIBS=ON \
     -DOQS_ENABLE_SIG_STFL_XMSS=ON \
     -DOQS_ENABLE_SIG_STFL_LMS=ON \
     -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
     -DOQS_DIST_BUILD=ON \
     -DOQS_BUILD_TYPE=Release \
     -DCMAKE_C_FLAGS="-march=native -O3" \
     -DCMAKE_CXX_FLAGS="-march=native -O3"
    ```
3. Build and install:
    ```bash
    make -j4
    sudo make install
    ```
    *Note if you do not have sudo/root access, skip `sudo make install` and take not of your `/path/to/liboqs`.

---

## Building this benchmark

### Windows (Visual Studio)

1. Open the **Developer Command Prompt for VS 2022**
2. Navigate to this repository folder.
3. Run the following commands (replace path if you did not install liboqs globally):
    ```cmd
    mkdir build
    cd build
    cmake .. -DCMAKE_PREFIX_PATH="C:\path\to\liboqs"
    cmake --build . --config Release
    ```
4. **Important:** Copy the `oqs.dll` file from your `liboqs/build/bin/Release` folder into this project's `build/Release` folder so the executable can find it. Also, copy sphincs_lib.dll from `build/libs/sphincs_lib` into the same folder.

### Linux

1. Navigate to this repository folder.
2. Run:
    ```bash
    mkdir build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="/path/to/liboqs"
    make
    ```
3. **Important:** Copy the `oqs.dll` file from your `liboqs/build/bin/Release` folder into this project's `build/Release` folder so the executable can find it. Also, copy sphincs_lib.dll from `build/libs/sphincs_lib` into the same folder.

---

# How to run

The project create two executables:
1. `benchmark`: A worker process that tests a single algorithm (do not run this directly).
2. `tester`: The controller that runs full suite.

**Run the tester:**

**Windows:**
```cmd
cd build/Release
tester.exe
```

**Linux:**
```bash
cd build/bin
./tester
```

The results will be saved to **`results.csv`**

## Custom library (libhbs)

Your own schemes live in `libs/hbs`. SPHINCS+ is split so hashes, WOTS+, FORS and Merkle trees can be reused when you add XMSS/LMS.

```
libs/hbs/
  include/hbs/hbs.h       list_schemes() / open("MY_SPHINCS-128f")
  src/crypto/             SHAKE256, RNG
  src/merkle/             treehash
  src/sphincs/            address, WOTS+, FORS, sign/verify
  src/registry.cpp        add a name here to expose a new scheme
```

Build **without** liboqs is supported: OQS schemes are skipped, custom ones still run.
Build **without** OpenSSL uses the bundled Keccak. Build **without** OpenMP
runs the same SPHINCS+ code on one thread. CMake picks OpenSSL first, then
links OpenMP if it is installed. The Makefile does the same probe.

```
# list whatever this binary actually contains
./benchmark --list
./tester --list
```

Thread cap for the custom schemes (so a run does not sit at 99% CPU):

```
HBS_THREADS=4 ./benchmark MY_SPHINCS-128f 2 0 1 1
HBS_THREADS=all ./benchmark MY_SPHINCS-128f 2 0 1 1   # every logical CPU
```

The GUI uses the same idea: the best toolkit that is installed, and a
fallback that needs nothing extra.

1. **Qt 6 or Qt 5** Widgets, when CMake finds it (Windows and Linux).
2. **Win32** on Windows when Qt is not installed.
3. **`hbs-tui`**, a terminal UI built from the C++ standard library. It is
   always compiled, including when Qt is missing on Linux. Vulkan is not used.

`Threads` `0` (or `auto` in the Qt window) is the automatic cap. A positive
number is passed as `HBS_THREADS` and `OMP_NUM_THREADS`.

```
./hbs-tui --list
./hbs-tui run MY_SPHINCS-128f 1 0
```

Known-answer tests against the official SPHINCS+ reference
(`THASH=simple`, `optrand = PK.seed`), plus one signature made with a
different `optrand` that must still verify:

```
make test
```

Byte-for-byte signatures: SHAKE 128f, 128s, 192f, 256f. Public keys: 192s
and 256s. The same files are checked with OpenMP on, with OpenMP off, and
with OpenSSL SHAKE256 when that library is what the binary was linked to.

CMake flags:

* `-DPQC_ENABLE_CUSTOM_SPHINCS=OFF` — do not build libhbs; `MY_SPHINCS-*` are skipped instead of a link error
* `-DPQC_REQUIRE_OQS=ON` — fail configure if liboqs is missing (default is skip)

