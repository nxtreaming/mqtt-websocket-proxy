This directory contains third-party dependencies for the project.

The recommended approach is to clone the required libraries as git submodules:

```
git submodule update --init --recursive
```

If network access is not available, you may manually download the following
projects and place them here:

- libuv -> `third_party/libuv`
- libwebsockets -> `third_party/libwebsockets`
- nlohmann/json -> `third_party/nlohmann`

Alternatively, configure CMake to use system-installed versions by enabling the
`USE_SYSTEM_LIBUV` and `USE_SYSTEM_LIBWEBSOCKETS` options.
