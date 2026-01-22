# pqc-hbs-benchmark
C++ Benchmarking tool for NIST Post-Quantum Hash-Based Signatures using the Open Quantum Safe library.

## Setting up

You must have the **Open Quantum Safe (liboqs)** library installed. Because this benchmark tests stateful schemes, **you must compile liboqs from source** with specific flags enabled.

## Security Warning

**DO NOT USE THE CUSTOM IMPLEMENTATION (`libs/sphincs_lib`) IN PRODUCTION**

The custom SPHINCS+ implementation include in this project ("MY_SPHINCS") is an **educational reference implementation**
* It is **not** constant-time (vulnerable to side-channel attacks).
* It does **not** wipe memory securely
* It uses a scalar implementation of Keccak (slower than AVX2)

It is intended solely for benchmarking algorithmic complexity against optimized libraries like `liboqs`.

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
    cmake .. -DBUILD_SHARED_LIBS=ON -DOQS_ENABLE_SIG_STFL_XMSS=ON -DOQS_ENABLE_SIG_STFL_LMS=ON -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON
    ```
3. Build and install:
    ```bash
    make -j4
    sudo make install
    ```

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
4. **Important:** Copy the `oqs.dll` file from your `liboqs/build/bin/Release` folder into this project's `build/Release` folder so the executable can find it.

### Linux

1. Navigate to this repository folder.
2. Run:
    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

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
