import { Transform, type Readable } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";
import type { FastifyInstance } from "fastify";
import { HttpError } from "./errors.js";

const DECODERS: Record<string, () => Transform> = {
  gzip: createGunzip,
  "x-gzip": createGunzip,
  deflate: createInflate,
  br: createBrotliDecompress,
};

/**
 * Decode compressed request bodies (Content-Encoding: gzip | deflate | br) so remote collectors
 * (Vector, OTel Collector, Fluent Bit) can compress telemetry. Fastify's bodyLimit is enforced on the
 * DECODED stream, which also bounds decompression bombs. Unknown encodings get 415.
 */
export function registerRequestDecompression(app: FastifyInstance): void {
  app.addHook("preParsing", async (request, _reply, payload) => {
    const raw = String(request.headers["content-encoding"] ?? "").trim().toLowerCase();
    if (!raw || raw === "identity") return payload;
    const make = DECODERS[raw];
    if (!make) throw new HttpError(415, "unsupported_encoding", `Content-Encoding '${raw}' is not supported (use gzip, deflate or br)`);
    let encoded = 0;
    const counter = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        encoded += chunk.length;
        cb(null, chunk);
      },
    });
    const decoded = (payload as Readable).pipe(counter).pipe(make());
    // Fastify compares Content-Length with the encoded size when receivedEncodedLength is present.
    Object.defineProperty(decoded, "receivedEncodedLength", { get: () => encoded });
    decoded.on("error", () => undefined);
    return decoded;
  });
}
