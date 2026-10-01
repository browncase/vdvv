import {
  ChannelCredentials,
  ClientReadableStream,
  InterceptingCall,
  Interceptor,
  Metadata,
  ServiceError,
  status,
} from "@grpc/grpc-js";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import bs58 from "bs58";
import { readFileSync } from "node:fs";
import {
  AuthServiceClient,
  GenerateAuthChallengeResponse,
  GenerateAuthTokensResponse,
  RefreshAccessTokenResponse,
  Role,
  Token,
} from "jito-ts/dist/gen/block-engine/auth";
import {
  BundleResult,
  DroppedReason,
  Rejected,
} from "jito-ts/dist/gen/block-engine/bundle";
import { Packet } from "jito-ts/dist/gen/block-engine/packet";
import {
  GetTipAccountsResponse,
  SearcherServiceClient,
  SendBundleResponse,
} from "jito-ts/dist/gen/block-engine/searcher";
import nacl from "tweetnacl";

const MAX_TXS = 5;
const TOKEN_SLACK_MS = 30_000;
const SIG_BATCH = 256;

/** Base class for everything thrown here; `ctx` carries the relevant ids. */
export class JitoError extends Error {
  constructor(
    msg: string,
    readonly ctx: Record<string, unknown> = {},
    opts?: ErrorOptions,
  ) {
    super(msg, opts);
    this.name = new.target.name;
  }
}

/** Challenge/token exchange with the block engine failed. */
export class AuthError extends JitoError {}

/** Bundle could not be built or was refused on submit. */
export class BundleError extends JitoError {}

type Cb<T> = (err: ServiceError | null, res: T) => void;
type Ctx = Record<string, unknown>;

function unary<T>(run: (cb: Cb<T>) => unknown): Promise<T> {
  return new Promise((resolve, reject) =>
    run((err, res) => (err ? reject(err) : resolve(res))),
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const rethrow =
  (E: typeof JitoError, msg: string, ctx: Ctx) =>
  (e: unknown): never => {
    throw new E(msg, ctx, { cause: e });
  };

function fresh(t?: Token): t is Token {
  if (!t) return false;
  if (!t.expiresAtUtc) return true;
  return t.expiresAtUtc.getTime() - Date.now() > TOKEN_SLACK_MS;
}

class Auth {
  private tok?: Token;
  private rtok?: Token;
  private inflight?: Promise<Token>;

  constructor(
    private readonly c: AuthServiceClient,
    private readonly kp: Keypair,
    private readonly url: string,
  ) {}

  async token(): Promise<string> {
    if (fresh(this.tok)) return this.tok.value;
    this.inflight ??= this.renew().finally(() => (this.inflight = undefined));
    return (await this.inflight).value;
  }

  private async renew(): Promise<Token> {
    const r = this.rtok;
    if (fresh(r)) {
      const res = await unary<RefreshAccessTokenResponse>((cb) =>
        this.c.refreshAccessToken({ refreshToken: r.value }, cb),
      ).catch(() => undefined);
      if (res?.accessToken) return (this.tok = res.accessToken);
    }
    return this.login();
  }

  private async login(): Promise<Token> {
    const pk = this.kp.publicKey;
    const ctx = { pubkey: pk.toBase58(), url: this.url };

    const { challenge } = await unary<GenerateAuthChallengeResponse>((cb) =>
      this.c.generateAuthChallenge(
        { role: Role.SEARCHER, pubkey: pk.toBytes() },
        cb,
      ),
    ).catch(rethrow(AuthError, "challenge request failed", ctx));

    const msg = `${pk.toBase58()}-${challenge}`;
    const sig = nacl.sign.detached(Buffer.from(msg, "utf8"), this.kp.secretKey);

    const res = await unary<GenerateAuthTokensResponse>((cb) =>
      this.c.generateAuthTokens(
        { challenge: msg, clientPubkey: pk.toBytes(), signedChallenge: sig },
        cb,
      ),
    ).catch(rethrow(AuthError, "token request failed", ctx));

    if (!res.accessToken || !res.refreshToken) {
      throw new AuthError("engine returned no tokens", ctx);
    }
    this.rtok = res.refreshToken;
    return (this.tok = res.accessToken);
  }
}

function bearer(auth: Auth): Interceptor {
  return (opts, next) =>
    new InterceptingCall(next(opts), {
      start(md, listener, nxt) {
        auth.token().then(
          (t) => {
            md.set("authorization", `Bearer ${t}`);
            nxt(md, listener);
          },
          (e: Error) =>
            listener.onReceiveStatus({
              code: status.UNAUTHENTICATED,
              details: e.message,
              metadata: new Metadata(),
            }),
        );
      },
    });
}

export type State = "pending" | "landed" | "dropped";

interface Entry {
  sig: string;
  at: number;
  state: State;
  why?: string;
}

/** Per-bundle outcome book; everything goes in as pending and gets marked once. */
export class Stats {
  private readonly m = new Map<string, Entry>();

  /** Register a freshly submitted bundle under its engine id and tip tx signature. */
  add(id: string, sig: string): void {
    this.m.set(id, { sig, at: Date.now(), state: "pending" });
  }

  /** Set the final state; later marks for the same id are ignored. */
  mark(id: string, state: State, why?: string): void {
    const e = this.m.get(id);
    if (e && e.state === "pending") Object.assign(e, { state, why });
  }

  /** `[id, sig]` pairs still pending and at least `olderThanMs` old. */
  pending(olderThanMs = 0): [string, string][] {
    const cut = Date.now() - olderThanMs;
    return [...this.m]
      .filter(([, e]) => e.state === "pending" && e.at <= cut)
      .map(([id, e]) => [id, e.sig]);
  }

  /** landed / (landed + dropped); pending bundles are excluded. NaN if nothing resolved. */
  rate(): number {
    const n = this.count("landed");
    return n / (n + this.count("dropped"));
  }

  /** Snapshot for logging. */
  summary(): {
    sent: number;
    landed: number;
    dropped: number;
    pending: number;
    rate: number;
    why: Record<string, number>;
  } {
    const why: Record<string, number> = {};
    for (const e of this.m.values()) {
      if (e.why) why[e.why] = (why[e.why] ?? 0) + 1;
    }
    return {
      sent: this.m.size,
      landed: this.count("landed"),
      dropped: this.count("dropped"),
      pending: this.count("pending"),
      rate: this.rate(),
      why,
    };
  }

  private count(s: State): number {
    let n = 0;
    for (const e of this.m.values()) if (e.state === s) n++;
    return n;
  }
}

/** Where the tip goes and who pays it. The tip tx is always the last one in the bundle. */
export interface TipOpts {
  payer: Keypair;
  to: PublicKey;
  lamports: number;
  blockhash: string;
}

function packet(tx: VersionedTransaction): Packet {
  const data = tx.serialize();
  return {
    data,
    meta: {
      size: data.length,
      addr: "0.0.0.0",
      port: 0,
      senderStake: 0,
      flags: undefined,
    },
  };
}

function reason(rej: Rejected): string {
  const hit = Object.entries(rej).find(([, v]) => v !== undefined);
  if (!hit) return "rejected";
  const [kind, v] = hit as [string, { msg?: string }];
  return v.msg ? `${kind}: ${v.msg}` : kind;
}

/** Single SystemProgram transfer as a signed v0 transaction. */
export function transfer(
  from: Keypair,
  to: PublicKey,
  lamports: number,
  blockhash: string,
): VersionedTransaction {
  const ix = SystemProgram.transfer({
    fromPubkey: from.publicKey,
    toPubkey: to,
    lamports,
  });
  const msg = new TransactionMessage({
    payerKey: from.publicKey,
    recentBlockhash: blockhash,
    instructions: [ix],
  }).compileToV0Message();
  const tx = new VersionedTransaction(msg);
  tx.sign([from]);
  return tx;
}

/** Authenticated searcher client that also keeps its own land-rate book. */
export class Searcher {
  readonly stats = new Stats();
  private readonly c: SearcherServiceClient;
  private readonly url: string;
  private stream?: ClientReadableStream<BundleResult>;

  /** `url` is host:port of the block engine, `kp` the keypair Jito approved for auth. */
  constructor(url: string, kp: Keypair) {
    const creds = ChannelCredentials.createSsl();
    const auth = new Auth(new AuthServiceClient(url, creds), kp, url);
    this.c = new SearcherServiceClient(url, creds, {
      interceptors: [bearer(auth)],
    });
    this.url = url;
  }

  /** Tip accounts the engine currently accepts; pick one at random per bundle. */
  async tipAccounts(): Promise<PublicKey[]> {
    const res = await unary<GetTipAccountsResponse>((cb) =>
      this.c.getTipAccounts({}, cb),
    ).catch(rethrow(BundleError, "getTipAccounts failed", { url: this.url }));
    return res.accounts.map((a) => new PublicKey(a));
  }

  /**
   * Appends the tip transfer to `txs`, submits, and books the bundle as pending.
   * `txs` must already be signed. Resolves to the engine's bundle id.
   */
  async send(txs: VersionedTransaction[], tip: TipOpts): Promise<string> {
    if (txs.length === 0 || txs.length >= MAX_TXS) {
      throw new BundleError(`need 1..${MAX_TXS - 1} txs before the tip`, {
        n: txs.length,
      });
    }
    const all = [
      ...txs,
      transfer(tip.payer, tip.to, tip.lamports, tip.blockhash),
    ];
    const sigs = all.map((t) => bs58.encode(t.signatures[0]));

    const res = await unary<SendBundleResponse>((cb) =>
      this.c.sendBundle(
        { bundle: { packets: all.map(packet), header: undefined } },
        cb,
      ),
    ).catch(rethrow(BundleError, "sendBundle refused", { sigs }));

    this.stats.add(res.uuid, sigs[sigs.length - 1]);
    return res.uuid;
  }

  /** Opens the bundle result stream and feeds it into `stats`. Reopens if the engine drops it. */
  watch(onErr: (e: ServiceError) => void = console.error): void {
    const s = this.c.subscribeBundleResults({});
    s.on("data", (r: BundleResult) => this.onResult(r));
    s.on("error", (e: ServiceError) => {
      if (e.code !== status.CANCELLED) onErr(e);
    });
    s.on("close", () => {
      if (this.stream === s) setTimeout(() => this.watch(onErr), 1_000);
    });
    this.stream = s;
  }

  /**
   * The stream reports accepted/rejected reliably but not always finalized,
   * so anything still pending after `maxAgeMs` is looked up over RPC via its tip signature.
   */
  async settle(conn: Connection, maxAgeMs = 60_000): Promise<void> {
    const pend = this.stats.pending(maxAgeMs);
    for (let i = 0; i < pend.length; i += SIG_BATCH) {
      const chunk = pend.slice(i, i + SIG_BATCH);
      const { value } = await conn.getSignatureStatuses(
        chunk.map(([, sig]) => sig),
        { searchTransactionHistory: true },
      );
      chunk.forEach(([id], j) => {
        const st = value[j];
        if (st && !st.err) this.stats.mark(id, "landed");
        else this.stats.mark(id, "dropped", st ? "TxFailed" : "NotOnChain");
      });
    }
  }

  /**
   * Blocks until every booked bundle has a final state, or `deadlineMs` has passed.
   * Stragglers older than `settleAfterMs` are resolved over RPC on each pass.
   */
  async drain(
    conn: Connection,
    deadlineMs: number,
    settleAfterMs = 30_000,
  ): Promise<void> {
    const end = Date.now() + deadlineMs;
    while (this.stats.pending().length > 0 && Date.now() < end) {
      await this.settle(conn, settleAfterMs);
      if (this.stats.pending().length > 0) await sleep(2_000);
    }
  }

  /** Cancels the result stream and closes the channel. */
  close(): void {
    const s = this.stream;
    this.stream = undefined;
    s?.cancel();
    this.c.close();
  }

  private onResult(r: BundleResult): void {
    if (r.finalized || r.processed) {
      this.stats.mark(r.bundleId, "landed");
    } else if (r.rejected) {
      this.stats.mark(r.bundleId, "dropped", reason(r.rejected));
    } else if (r.dropped) {
      this.stats.mark(r.bundleId, "dropped", DroppedReason[r.dropped.reason]);
    }
  }
}

export interface Cfg {
  keypair: string;
  engine: string;
  rpc: string;
  tip: number;
  count: number;
  waitMs: number;
}

function flags(argv: string[]): Map<string, string> {
  const m = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (!k.startsWith("--") || v === undefined) {
      throw new Error(`expected --flag value, got ${k}`);
    }
    m.set(k.slice(2), v);
  }
  return m;
}

function int(v: string, what: string): number {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${what}: bad int ${v}`);
  return n;
}

/**
 * `--flag value` pairs win over env vars; anything without a default is required.
 * Flags: keypair, engine, rpc, tip, count, wait.
 */
export function parseArgs(argv: string[]): Cfg {
  const f = flags(argv);
  const get = (k: string, env: string, dflt?: string): string => {
    const v = f.get(k) ?? process.env[env] ?? dflt;
    if (v === undefined) throw new Error(`missing --${k} or ${env}`);
    return v;
  };
  return {
    keypair: get("keypair", "KEYPAIR"),
    engine: get("engine", "BLOCK_ENGINE_URL"),
    rpc: get("rpc", "RPC_URL"),
    tip: int(get("tip", "TIP_LAMPORTS"), "tip"),
    count: int(get("count", "BUNDLE_COUNT"), "count"),
    waitMs: int(get("wait", "WAIT_MS", "120000"), "wait"),
  };
}

/** Reads a solana-cli style JSON keypair file. */
export function loadKeypair(path: string): Keypair {
  const raw = JSON.parse(readFileSync(path, "utf8")) as number[];
  return Keypair.fromSecretKey(Uint8Array.from(raw));
}

async function main(cfg: Cfg): Promise<void> {
  const conn = new Connection(cfg.rpc, "confirmed");
  const kp = loadKeypair(cfg.keypair);
  const s = new Searcher(cfg.engine, kp);

  s.watch();
  const tips = await s.tipAccounts();
  if (tips.length === 0) {
    throw new BundleError("engine returned no tip accounts", {
      url: cfg.engine,
    });
  }

  for (let i = 0; i < cfg.count; i++) {
    const { blockhash } = await conn.getLatestBlockhash();
    const tx = transfer(kp, kp.publicKey, 1, blockhash);
    const to = tips[Math.floor(Math.random() * tips.length)];
    try {
      const id = await s.send([tx], {
        payer: kp,
        to,
        lamports: cfg.tip,
        blockhash,
      });
      console.log("sent", id);
    } catch (e) {
      if (!(e instanceof JitoError)) throw e;
      console.error(e.name, e.message, e.ctx, e.cause);
    }
    await sleep(3_000);
  }

  await s.drain(conn, cfg.waitMs);
  console.log(s.stats.summary());
  s.close();
}

if (require.main === module) {
  main(parseArgs(process.argv.slice(2))).catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
