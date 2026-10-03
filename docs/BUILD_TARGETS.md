# Native Linux build targets

TLSVPN publishes a compatibility-first native Linux matrix. Generic artifact names remain stable, while CPU/ISA-specific variants add optional compile-time optimization.

## AMD64

| Artifact | Go setting | Minimum target | Recommended use |
|---|---|---|---|
| `tlsvpn_linux_amd64` | `GOAMD64=v1` | baseline x86-64 | safest/default choice |
| `tlsvpn_linux_amd64_v2` | `GOAMD64=v2` | SSE3/SSSE3/SSE4.x, POPCNT, CMPXCHG16B, etc. | older but capable x86-64 servers |
| `tlsvpn_linux_amd64_v3` | `GOAMD64=v3` | AVX, AVX2, BMI1/2, FMA, F16C, LZCNT, MOVBE, OSXSAVE | preferred modern-server optimized build |
| `tlsvpn_linux_amd64_v4` | `GOAMD64=v4` | v3 plus AVX-512 F/BW/CD/DQ/VL | only CPUs with the required AVX-512 feature set |

Higher GOAMD64 levels allow the Go compiler to emit instructions from the selected minimum ISA. They are not universally faster for every workload, so throughput should be benchmarked on the actual machine. A binary built for a higher level will not run on a CPU that does not satisfy that level.

## ARM

| Artifact | Go setting | Notes |
|---|---|---|
| `tlsvpn_linux_arm64` | `GOARM64=v8.0` | broad ARM64 compatibility baseline |
| `tlsvpn_linux_arm64_v8.2` | `GOARM64=v8.2` | optimized minimum for ARMv8.2-A class systems such as RK3588 |
| `tlsvpn_linux_arm_v5` | `GOARM=5` | legacy 32-bit ARM |
| `tlsvpn_linux_arm_v6` | `GOARM=6` | ARMv6 |
| `tlsvpn_linux_arm` | Go cross-compile default `GOARM=7` | existing ARMv7-compatible artifact name retained for compatibility |

## Other Linux architectures

The release matrix also includes:

- `386`
- `mips`, `mipsle`
- `mips64`, `mips64le`
- `riscv64`
- `ppc64`, `ppc64le`
- `ppc64le_power9` (`GOPPC64=power9`)
- `ppc64le_power10` (`GOPPC64=power10`)
- `s390x`
- `loong64`

## Build locally

List the complete default release matrix without compiling:

```bash
./scripts/build.sh --list
```

Build the full Linux matrix:

```bash
HOST_ALIAS=0 ./scripts/build.sh linux
```

Build individual optimized variants:

```bash
./scripts/build.sh linux/amd64@v3
./scripts/build.sh linux/arm64@v8.2
./scripts/build.sh linux/ppc64le@power10
./scripts/build.sh linux/riscv64@rva22u64
```

The `@variant` suffix maps to the architecture-specific Go build variable:

- `amd64` → `GOAMD64`
- `arm64` → `GOARM64`
- `arm` → `GOARM`
- `ppc64` / `ppc64le` → `GOPPC64`
- `riscv64` → `GORISCV64`

Successful native builds write `bin/SHA256SUMS-native.txt` covering all generated `tlsvpn_*` native binaries.
