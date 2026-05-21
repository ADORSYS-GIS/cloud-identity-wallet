# Link Time Optimizations

To reduce build times, especially during development, the use of faster alternative linker instead of the platform default is recommended.

This project is primarily optimized for Unix-like (Linux and macOS) development environments.

> ⚠️ These optimizations are recommended but not strictly required.  
> If the required linker is not available, Cargo will fall back to the system default.

## Platform Support

| Platform              | Status         | Notes                                        |
| --------------------- | -------------- | -------------------------------------------- |
| Linux                 | ✅ Supported   | Uses `mold` for significantly faster linking |
| macOS (Apple Silicon) | ✅ Supported   | Uses Apple’s default `ld_prime` linker       |
| macOS (Intel)         | ✅ Supported   | Uses LLVM’s `lld` for faster linking         |
| Windows               | ❌ Unsupported | Not currently supported                      |

## **Installation Instructions**

### **Linux**

On Linux, we recommend using [`mold`](https://github.com/rui314/mold), a high-performance drop-in replacement for `GNU ld`.  
On Debian and Debian-based distributions, `mold` and the required linker driver ([`clang`](https://clang.llvm.org/)) can be installed via `apt`:

```sh
sudo apt update
sudo apt install mold clang
```

For other Linux distributions or package managers, refer to the [official mold installation guide](https://github.com/rui314/mold/#installation).

To explicitly instruct `Cargo` to use `mold`, add the following to `.cargo/config.toml`:

```toml
[target.'cfg(target_os = "linux")']
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

### **macOS**

Apple Silicon Macs usually ship with `ld_prime`, Apple’s modern linker, which already provides fast link times.

On Intel-based macOS, we recommend using LLVM’s linker [`lld`](https://lld.llvm.org/).  
Ensure [Xcode Command Line Tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools/) are installed, then install [`lld`](https://lld.llvm.org/) using [Homebrew](https://brew.sh/):

```sh
xcode-select --install  # Install Xcode Command Line Tools
brew install lld        # Install LLVM linker
```

Cargo Configuration (Optional)

```toml
[target.x86_64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

## **Verification**

Ensure the linkers are correctly installed:

```sh
mold --version  # Linux
lld --version   # macOS
```

## **Testing the Setup**

To confirm `mold` is being used, inspect the `.comment` section of a compiled executable:

```sh
readelf -p .comment <executable-file>
```

If `mold` is used, you should see an entry similar to:

```sh
String dump of section '.comment':
  [    2b]  mold 9a1679b47d9b22012ec7dfbda97c8983956716f7
```
