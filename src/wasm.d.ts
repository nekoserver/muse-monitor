// Type declarations for the wasm-tailscale package's non-TS assets and the
// Go runtime globals. This file is intentionally a script (no top-level
// import/export): ambient `declare module` statements in a module .d.ts
// were not picked up by this TypeScript version, while the script form
// resolves them.
declare module "@ai-ecoverse/wasm-tailscale/wasm_exec.js";

declare module "@ai-ecoverse/wasm-tailscale/main.wasm" {
  const wasmModule: WebAssembly.Module;
  export default wasmModule;
}

declare class Go {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

/** An Error instead of a node when the backend can't be built (for example, stateStorage threw). */
declare function newIPN(
  config: import("./wasm-ipn").IPNConfig,
): import("./wasm-ipn").IPN | Error;
