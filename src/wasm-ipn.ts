// IPN interface definitions for @ai-ecoverse/wasm-tailscale, copied
// verbatim from the package's index.d.ts (1.104.1-13).
//
// Kept as a local module (not an ambient declaration) because the
// package's package.json "exports" map has no "." entry, so a plain
// `import ... from "@ai-ecoverse/wasm-tailscale"` does not resolve under
// bundler module resolution.

  export interface IPNConfig {
    /**
     * Where the node keeps its state: `_machinekey`, `log-policy` and the
     * profile, which with `ephemeral: false` holds the node's private key.
     * Treat it as a secret. The auth key is never written here. Called
     * synchronously from Go: don't call back into the IPN from it.
     */
    stateStorage?: { getState(id: string): string; setState(id: string, value: string): void };
    /** Used for one login only, never stored. */
    authKey?: string;
    controlURL?: string;
    hostname?: string;
    exitNode?: string;
    ephemeral?: boolean;
    logUpload?: boolean;
  }

  export interface IPNCallbacks {
    notifyState(state: string): void;
    notifyNetMap(netMap: string): void;
    notifyBrowseToURL(url: string): void;
    /** A callback that threw, or "Tailscale could not start: …" when run()'s start failed. */
    notifyPanicRecover(error: string): void;
  }

  export interface IPNResponse {
    status: number;
    statusText: string;
    url: string;
    headers: [string, string][];
    read(): Promise<Uint8Array | null>;
    cancel(): void;
  }

  export interface IPNConn {
    localAddr: string;
    remoteAddr: string;
    read(): Promise<Uint8Array | null>;
    write(bytes: Uint8Array): Promise<number>;
    /** shutdown(SHUT_WR): the peer reads the end of the stream. */
    closeWrite(): void;
    /** After close(), don't call this connection's functions: they are released about a second later. */
    close(): void;
  }

  export interface IPNWebSocketRequest {
    /** ws:, wss:, http: or https:. wss: is verified against the bundled roots. */
    url: string;
    protocols?: string[] | string;
    /** Sent with the handshake, except Host, Sec-WebSocket-*, Cookie, Content-Length, Connection and the headers it names, Keep-Alive, Proxy-Authorization, Proxy-Authenticate, Proxy-Connection, TE, Trailer, Transfer-Encoding and Upgrade. */
    headers?: [string, string][];
    /** Cancels the handshake (rejecting with signal.reason) and closes an open socket with 1001, dropping what send() queued; a write in progress is cancelled, which tears the connection down (1006). */
    signal?: AbortSignal;
  }

  export interface IPNWebSocketClose {
    code: number;
    reason: string;
  }

  export interface IPNWebSocket {
    /** The subprotocol the server chose, or "". */
    readonly protocol: string;
    /** Bytes given to send() and not yet written. */
    readonly buffered: number;
    /** An Error with code EPIPE once closing, or EMSGSIZE over 64 MiB (which also closes with 1009). */
    send(data: string | Uint8Array | ArrayBuffer): undefined | Error;
    /** Whole messages: strings for text, Uint8Arrays for binary. return() drops what's left. */
    readonly messages: AsyncIterableIterator<string | Uint8Array>;
    /** A code a client can't send becomes 1000; the reason is cut to 123 bytes at a UTF-8 boundary. */
    close(code?: number, reason?: string): void;
    /** The close frame that ended the socket; 1005 without a code, 1006 without a close frame. */
    readonly closed: Promise<IPNWebSocketClose>;
  }

  export interface IPN {
    run(callbacks: IPNCallbacks): void;
    /** Refused before run(); waits for run()'s start (and runs it again if it failed), and re-applies shields up, the control URL, hostname and routes first. */
    login(authKey?: string): void;
    logout(): void;
    fetch(request: {
      url: string;
      method?: string;
      headers?: [string, string][];
      body?: Uint8Array;
      manualRedirects?: boolean;
      encodedBodies?: boolean;
    }): Promise<IPNResponse>;
    dial(network: 'tcp' | 'udp', addr: string): Promise<IPNConn>;
    /** A refused handshake rejects with an Error whose status is the HTTP status; redirects aren't followed. */
    websocket(request: IPNWebSocketRequest): Promise<IPNWebSocket>;
    setExitNode(expr: string): Promise<void>;
    /** JSON. Safe in the notify* callbacks (they run on their own task); returns an Error inside stateStorage callbacks instead of hanging. */
    status(): string | Error;
  }
