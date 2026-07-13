# TinyGo VLESS lower-bound experiment

This deliberately incomplete parser exists only to measure the most favorable
Go/Wasm case considered by `decisions/0001-worker-runtime.md`. It is not linked
into the Worker and must not be treated as a second protocol implementation.

Build with the pinned research toolchain:

```sh
tinygo build -target wasm -no-debug -opt=2 -o /tmp/tinygo-vless.wasm ./research/experiments/tinygo-vless
```

The function omits authentication, streaming state, JavaScript/Go memory-copy
glue, address rendering, destination policy, and Streams API bridging. Its size
is therefore a lower bound. The production TypeScript parser remains canonical.
