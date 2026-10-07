import { isCve } from "../core/indicators.js";
import { arr, isRecord, num, str } from "../core/json.js";
import { payloadToText } from "../core/records.js";
import { toIso } from "../core/time.js";
import { EngineClient, type EngineClientOptions } from "../http/client.js";

/**
 * FIRST EPSS (Exploit Prediction Scoring System) — free, key-less. Two sources:
 *  - daily CSV (`epss_scores-current.csv.gz`, header comment with model version & date);
 *  - REST API `GET https://api.first.org/data/v1/epss?cve=CVE-…,CVE-…`.
 * Scores are probabilities (0..1) of exploitation activity in the next 30 days.
 */
export const EPSS_SOURCES = {
  apiOrigin: "https://api.first.org",
  apiPath: "/data/v1/epss",
  csvOrigin: "https://epss.cyentia.com",
  csvPath: "/epss_scores-current.csv.gz",
} as const;

export interface EpssScore {
  cve: string;
  epss: number;
  percentile: number;
  date: string | null;
}

export class EpssTable {
  private readonly scores = new Map<string, EpssScore>();
  modelVersion: string | null = null;
  scoreDate: string | null = null;
  invalidRows = 0;

  get size(): number {
    return this.scores.size;
  }

  get(cve: string): EpssScore | undefined {
    return this.scores.get(cve.trim().toUpperCase());
  }

  set(score: EpssScore): void {
    this.scores.set(score.cve, score);
  }

  merge(other: EpssTable): this {
    for (const s of other.values()) this.set(s);
    this.modelVersion = other.modelVersion ?? this.modelVersion;
    this.scoreDate = other.scoreDate ?? this.scoreDate;
    return this;
  }

  values(): EpssScore[] {
    return [...this.scores.values()];
  }

  /** Parse the daily CSV (plain text, bytes or gzip bytes). */
  static fromCsv(input: string | Uint8Array): EpssTable {
    const text = payloadToText(input) ?? "";
    const table = new EpssTable();
    let header: string[] | null = null;
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line === "") continue;
      if (line.startsWith("#")) {
        const mv = /model_version:([^,]+)/.exec(line);
        const sd = /score_date:([^,]+)/.exec(line);
        if (mv) table.modelVersion = mv[1]?.trim() ?? null;
        if (sd) table.scoreDate = toIso(sd[1]?.trim()) ?? null;
        continue;
      }
      const cols = line.split(",").map((c) => c.trim());
      if (!header) {
        header = cols.map((c) => c.toLowerCase());
        continue;
      }
      const cve = cols[header.indexOf("cve")];
      const epss = num(cols[header.indexOf("epss")]);
      const pct = num(cols[header.indexOf("percentile")]);
      if (!cve || !isCve(cve) || epss === undefined || epss < 0 || epss > 1 || pct === undefined || pct < 0 || pct > 1) {
        table.invalidRows++;
        continue;
      }
      table.set({ cve: cve.toUpperCase(), epss, percentile: pct, date: table.scoreDate });
    }
    return table;
  }

  /** Parse an API response (`{status:"OK", data:[{cve, epss, percentile, date}]}`). */
  static fromApi(json: unknown): EpssTable {
    const table = new EpssTable();
    const data = isRecord(json) ? arr(json["data"]) : [];
    for (const row of data) {
      if (!isRecord(row)) continue;
      const cve = str(row["cve"]);
      const epss = num(row["epss"]);
      const pct = num(row["percentile"]);
      if (!cve || !isCve(cve) || epss === undefined || pct === undefined || epss < 0 || epss > 1 || pct < 0 || pct > 1) {
        table.invalidRows++;
        continue;
      }
      const date = toIso(str(row["date"])) ?? null;
      table.set({ cve: cve.toUpperCase(), epss, percentile: pct, date });
      table.scoreDate = table.scoreDate ?? date;
    }
    if (isRecord(json)) table.modelVersion = str(json["model_version"]) ?? table.modelVersion;
    return table;
  }
}

export function createEpssClient(opts: Omit<EngineClientOptions, "engine" | "baseUrl"> & { baseUrl?: string } = {}): EngineClient {
  return new EngineClient({ ...opts, engine: "first_epss", baseUrl: opts.baseUrl ?? EPSS_SOURCES.apiOrigin });
}

/** Look up scores for specific CVEs via the API, batching to keep URLs short. */
export async function fetchEpssScores(client: EngineClient, cves: string[], opts: { batchSize?: number } = {}): Promise<EpssTable> {
  const unique = [...new Set(cves.map((c) => c.trim().toUpperCase()).filter(isCve))];
  const size = Math.min(Math.max(opts.batchSize ?? 100, 1), 100);
  const table = new EpssTable();
  for (let i = 0; i < unique.length; i += size) {
    const batch = unique.slice(i, i + size);
    const res = await client.get<unknown>(EPSS_SOURCES.apiPath, { query: { cve: batch.join(",") } });
    table.merge(EpssTable.fromApi(res.data));
  }
  return table;
}
