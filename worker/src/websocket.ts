import { authenticateUser, type Credential } from "./auth";
import { resolvePublicDNS } from "./dns";
import {
  parseAllowedPorts,
  resolveAndValidateDestination,
  type DestinationPolicy,
  type DNSResolver,
  type ResolvedDestination
} from "./policy";
import { connectTCP } from "./tcp";
import { buildVlessResponseHeader, VlessHandshakeParser, VlessProtocolError } from "./protocol/vless";

const MAX_QUEUED_CLIENT_BYTES = 1024 * 1024;
const WEBSOCKET_SEND_CHUNK_BYTES = 64 * 1024;
const MAX_WEBSOCKET_CLOSE_REASON_BYTES = 123;

export interface SessionOptions {
  readonly expectedHost: string;
  readonly allowedPorts: string;
  readonly handshakeTimeoutMs: number;
  readonly connectTimeoutMs: number;
  readonly idleTimeoutMs: number;
  readonly sessionTimeoutMs: number;
}

export interface TunnelSessionDependencies {
  readonly resolveDNS: DNSResolver;
  readonly connect: (
    destination: ResolvedDestination,
    timeoutMilliseconds: number,
    signal?: AbortSignal
  ) => Promise<Socket>;
  readonly now: () => Date;
}

const DEFAULT_DEPENDENCIES: TunnelSessionDependencies = {
  resolveDNS: resolvePublicDNS,
  connect: connectTCP,
  now: () => new Date()
};

function messageLength(data: unknown): number | undefined {
  if (data instanceof ArrayBuffer) return data.byteLength;
  if (ArrayBuffer.isView(data)) return data.byteLength;
  if (data instanceof Blob) return data.size;
  return undefined;
}

async function asBytes(data: unknown): Promise<Uint8Array | undefined> {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  }
  if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  return undefined;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function reciprocalClose(event: CloseEvent): { readonly code: number; readonly reason?: string } {
  const receivedCodeIsSafe =
    event.code === 1000 ||
    (event.code >= 1001 && event.code <= 1014 && ![1004, 1005, 1006].includes(event.code)) ||
    (event.code >= 3000 && event.code <= 4999);
  if (!receivedCodeIsSafe) return { code: 1000 };
  const reason =
    new TextEncoder().encode(event.reason).byteLength <= MAX_WEBSOCKET_CLOSE_REASON_BYTES ? event.reason : undefined;
  return reason === undefined ? { code: event.code } : { code: event.code, reason };
}

export class TunnelSession {
  readonly #webSocket: WebSocket;
  readonly #credential: Credential;
  readonly #options: SessionOptions;
  readonly #policy: DestinationPolicy;
  readonly #dependencies: TunnelSessionDependencies;
  readonly #parser = new VlessHandshakeParser();
  readonly #handshakeTimer: ReturnType<typeof setTimeout>;
  readonly #sessionTimer: ReturnType<typeof setTimeout>;
  #idleTimer: ReturnType<typeof setTimeout>;
  #socket: Socket | undefined;
  #writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
  #dnsAbortController: AbortController | undefined;
  #dnsTimer: ReturnType<typeof setTimeout> | undefined;
  #connectAbortController: AbortController | undefined;
  #messageChain: Promise<void> = Promise.resolve();
  #queuedClientBytes = 0;
  #authenticated = false;
  #closed = false;
  #responseSent = false;

  constructor(
    webSocket: WebSocket,
    credential: Credential,
    options: SessionOptions,
    dependencies: TunnelSessionDependencies = DEFAULT_DEPENDENCIES
  ) {
    this.#webSocket = webSocket;
    this.#credential = credential;
    this.#options = options;
    this.#dependencies = dependencies;
    this.#policy = {
      expectedHost: options.expectedHost,
      allowedPorts: parseAllowedPorts(options.allowedPorts)
    };
    this.#handshakeTimer = setTimeout(() => this.#requestClose(1008, "policy violation"), options.handshakeTimeoutMs);
    this.#sessionTimer = setTimeout(() => this.#requestClose(1000, "session complete"), options.sessionTimeoutMs);
    this.#idleTimer = setTimeout(() => this.#requestClose(1000, "session idle"), options.idleTimeoutMs);
  }

  start(): void {
    this.#webSocket.binaryType = "arraybuffer";
    this.#webSocket.accept({ allowHalfOpen: true });
    this.#webSocket.addEventListener("message", (event) => this.#enqueueMessage(event.data));
    this.#webSocket.addEventListener("close", (event) => {
      const reciprocal = reciprocalClose(event);
      this.#requestClose(reciprocal.code, reciprocal.reason);
    });
    this.#webSocket.addEventListener("error", () => this.#requestClose(1011, "session failed"));
  }

  #touch(): void {
    clearTimeout(this.#idleTimer);
    this.#idleTimer = setTimeout(() => this.#requestClose(1000, "session idle"), this.#options.idleTimeoutMs);
  }

  #enqueueMessage(data: unknown): void {
    if (this.#closed) return;
    const byteLength = messageLength(data);
    if (byteLength === undefined) {
      this.#requestClose(1003, "binary data required");
      return;
    }
    this.#queuedClientBytes += byteLength;
    if (this.#queuedClientBytes > MAX_QUEUED_CLIENT_BYTES) {
      this.#requestClose(1009, "message queue exceeded");
      return;
    }
    this.#messageChain = this.#messageChain
      .then(async () => {
        const bytes = await asBytes(data);
        if (bytes === undefined) {
          this.#requestClose(1003, "binary data required");
          return;
        }
        await this.#handleClientBytes(bytes);
      })
      .catch(() => this.#requestClose(this.#authenticated ? 1011 : 1008, "session failed"))
      .finally(() => {
        this.#queuedClientBytes -= byteLength;
      });
  }

  async #handleClientBytes(bytes: Uint8Array): Promise<void> {
    if (this.#closed) return;
    this.#touch();
    if (this.#writer !== undefined) {
      await this.#writer.write(bytes);
      return;
    }

    let parsed;
    try {
      parsed = this.#parser.push(bytes);
    } catch (error) {
      if (error instanceof VlessProtocolError) {
        this.#requestClose(1008, "policy violation");
        return;
      }
      throw error;
    }
    if (parsed === undefined) return;

    if (
      (this.#credential.expiresAt !== undefined && this.#dependencies.now() >= this.#credential.expiresAt) ||
      !authenticateUser(parsed.request.userId, this.#credential.uuid)
    ) {
      this.#requestClose(1008, "policy violation");
      return;
    }
    this.#authenticated = true;
    clearTimeout(this.#handshakeTimer);

    const dnsController = parsed.request.destination.type === "domain" ? new AbortController() : undefined;
    let dnsTimer: ReturnType<typeof setTimeout> | undefined;
    if (dnsController !== undefined) {
      this.#dnsAbortController = dnsController;
      dnsTimer = setTimeout(() => {
        if (this.#dnsAbortController === dnsController) {
          this.#requestClose(1011, "session failed");
        }
      }, this.#options.connectTimeoutMs);
      this.#dnsTimer = dnsTimer;
    }

    let destination: ResolvedDestination;
    try {
      destination = await resolveAndValidateDestination(
        parsed.request.destination,
        this.#policy,
        this.#dependencies.resolveDNS,
        dnsController?.signal
      );
    } finally {
      dnsController?.abort();
      if (dnsTimer !== undefined) clearTimeout(dnsTimer);
      if (this.#dnsAbortController === dnsController) this.#dnsAbortController = undefined;
      if (this.#dnsTimer === dnsTimer) this.#dnsTimer = undefined;
    }
    if (this.#closed) return;
    const connectController = new AbortController();
    this.#connectAbortController = connectController;
    let socket: Socket;
    try {
      socket = await this.#dependencies.connect(destination, this.#options.connectTimeoutMs, connectController.signal);
    } finally {
      if (this.#connectAbortController === connectController) this.#connectAbortController = undefined;
    }
    if (this.#closed) {
      await socket.close();
      return;
    }
    this.#socket = socket;
    this.#writer = socket.writable.getWriter();
    this.#sendResponseHeader();
    if (parsed.initialPayload.byteLength > 0) await this.#writer.write(parsed.initialPayload);
    void this.#pumpDestination(socket).catch(() => this.#requestClose(1011, "session failed"));
  }

  #sendResponseHeader(): void {
    if (this.#responseSent || this.#closed) return;
    this.#responseSent = true;
    this.#webSocket.send(buildVlessResponseHeader());
  }

  async #sendDestinationBytes(bytes: Uint8Array): Promise<void> {
    for (let offset = 0; offset < bytes.byteLength && !this.#closed; offset += WEBSOCKET_SEND_CHUNK_BYTES) {
      this.#webSocket.send(bytes.subarray(offset, offset + WEBSOCKET_SEND_CHUNK_BYTES));
      // The Workers server-side WebSocket API exposes no bufferedAmount. Yielding after each
      // bounded send lets the runtime drain its transport queue and prevents an application queue.
      await delay(0);
    }
  }

  async #pumpDestination(socket: Socket): Promise<void> {
    const reader = socket.readable.getReader();
    try {
      while (!this.#closed) {
        const result = await reader.read();
        if (result.done) {
          // The destination closed only its readable half. Keep the client-to-destination
          // direction writable until the client closes or a bounded session timer expires.
          return;
        }
        this.#touch();
        await this.#sendDestinationBytes(result.value);
      }
    } finally {
      reader.releaseLock();
    }
  }

  #requestClose(code?: number, reason?: string): void {
    if (this.#closed) return;
    this.#closed = true;
    clearTimeout(this.#handshakeTimer);
    clearTimeout(this.#sessionTimer);
    clearTimeout(this.#idleTimer);
    const dnsAbortController = this.#dnsAbortController;
    this.#dnsAbortController = undefined;
    if (this.#dnsTimer !== undefined) {
      clearTimeout(this.#dnsTimer);
      this.#dnsTimer = undefined;
    }
    dnsAbortController?.abort();
    const connectAbortController = this.#connectAbortController;
    this.#connectAbortController = undefined;
    connectAbortController?.abort();
    if (code !== undefined) {
      try {
        this.#webSocket.close(code, reason);
      } catch {
        // Cleanup must still run if the transport races into a closed state.
      }
    }
    void this.#cleanup();
  }

  async #cleanup(): Promise<void> {
    const writer = this.#writer;
    this.#writer = undefined;
    const socket = this.#socket;
    this.#socket = undefined;

    // Start the underlying socket close immediately. A backpressured
    // WritableStream close must not indefinitely delay resource release.
    let socketClose = Promise.resolve();
    if (socket !== undefined) {
      try {
        socketClose = socket.close().catch(() => undefined);
      } catch {
        // A synchronous close failure still leaves no further close API to invoke.
      }
    }
    if (writer !== undefined) {
      try {
        await writer.close();
      } catch {
        // Socket shutdown races are expected during cancellation.
      }
      try {
        writer.releaseLock();
      } catch {
        // The stream may already have released its lock after an error.
      }
    }
    await socketClose;
  }
}
