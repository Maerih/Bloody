import { PLANS, type Organization } from "@bloody/contracts";
import { Archive, Save } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useUpdateOrganization } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { Input } from "../../components/Form";
import { formatInteger } from "../../lib/format";

function RetentionRow({ org, max }: { org: Organization; max: number }) {
  const session = useSession();
  const update = useUpdateOrganization(org.id);
  const [value, setValue] = useState(String(org.retentionDays));
  const n = Number(value);
  const valid = /^\d+$/.test(value.trim()) && n >= 1 && n <= max;
  const canWrite = session.can("org:write", org.id);
  return (
    <li className="flex flex-wrap items-center gap-2 px-3 py-2">
      <span className="min-w-0 flex-1">
        <span className="block font-medium text-fg">{org.name}</span>
        <span className="block text-2xs text-fg-subtle">Events older than this are dropped from hot search; monthly partitions beyond the plan maximum are removed.</span>
      </span>
      {canWrite ? (
        <>
          <label className="flex items-center gap-1.5 text-sm text-fg-muted">
            <Input value={value} onChange={(e) => setValue(e.target.value)} inputMode="numeric" className="h-7 w-20 text-right" aria-label={`Retention days for ${org.name}`} aria-invalid={!valid} />
            days
          </label>
          <Button size="xs" icon={Save} disabled={!valid || n === org.retentionDays} loading={update.isPending} onClick={() => update.mutate({ retentionDays: n })}>
            Save
          </Button>
        </>
      ) : (
        <Badge>{formatInteger(org.retentionDays)} days</Badge>
      )}
      {!valid ? <span className="w-full text-right text-2xs text-sev-critical">Between 1 and {formatInteger(max)} days on your plan</span> : null}
      {update.isError ? <span className="w-full text-right text-2xs text-sev-critical">{errorMessage(update.error)}</span> : null}
      {update.isSuccess && n === org.retentionDays ? <span className="w-full text-right text-2xs text-healthy">Saved</span> : null}
    </li>
  );
}

/** Per-organization event retention within the plan maximum (data lifecycle / archive). */
export function RetentionPanel() {
  const session = useSession();
  const plan = PLANS[session.plan];
  const orgs = session.organizationId ? session.organizations.filter((o) => o.id === session.organizationId) : session.organizations;
  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
      <Card title="Event retention" count={orgs.length} padded={false} info="Retention applies per organization inside the account's monthly event partitions.">
        {orgs.length === 0 ? (
          <p className="p-3 text-sm text-fg-muted">No organizations.</p>
        ) : (
          <ul className="divide-y divide-line">
            {orgs.map((o) => (
              <RetentionRow key={o.id} org={o} max={plan.limits.retentionDays} />
            ))}
          </ul>
        )}
      </Card>
      <Card title="Lifecycle & archive" actions={<Archive size={14} className="text-fg-muted" aria-hidden />}>
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between gap-2">
            <dt className="text-fg-muted">Plan</dt>
            <dd className="font-medium">{plan.name}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-fg-muted">Maximum hot retention</dt>
            <dd className="font-medium">{formatInteger(plan.limits.retentionDays)} days</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-fg-muted">Ingestion limit</dt>
            <dd className="font-medium">{formatInteger(plan.limits.eventsPerDay)} events/day</dd>
          </div>
        </dl>
        <p className="mt-3 text-xs text-fg-muted">Raw events and evidence are preserved in object storage (S3 API) under tenant/organization prefixes; investigation evidence keeps its chain of custody independently of event retention.</p>
      </Card>
    </div>
  );
}
