import type { NotificationChannelKind, ReportFormat, ReportType } from "@bloody/contracts";
import { CircleCheck, Hash, Mail, MessageSquare, Radio, Webhook, type LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../api/client";
import { useCreateReportSchedule, useNotificationChannels } from "../api/hooks";
import { useSession } from "../app/session";
import { describeCron } from "../lib/format";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";
import { Checkbox, Field, Input, Select } from "./Form";
import { Dialog } from "./Overlay";
import { REPORT_FORMATS, REPORT_PERIODS, reportLabel } from "../lib/reports";
import { SkeletonText } from "./Skeleton";

export const CHANNEL_ICONS: Record<NotificationChannelKind, LucideIcon> = {
  email: Mail,
  slack: Hash,
  teams: MessageSquare,
  webhook: Webhook,
  syslog: Radio,
  in_app: MessageSquare,
};

type Frequency = "daily" | "weekdays" | "weekly" | "monthly" | "custom";
const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

export function buildCron(freq: Frequency, time: string, weekday: number, monthDay: number, custom: string): string {
  const [h = "7", m = "0"] = time.split(":");
  const hour = String(Math.min(23, Math.max(0, Number(h) || 0)));
  const minute = String(Math.min(59, Math.max(0, Number(m) || 0)));
  switch (freq) {
    case "daily":
      return `${minute} ${hour} * * *`;
    case "weekdays":
      return `${minute} ${hour} * * 1-5`;
    case "weekly":
      return `${minute} ${hour} * * ${weekday}`;
    case "monthly":
      return `${minute} ${hour} ${monthDay} * *`;
    default:
      return custom.trim();
  }
}

/** Minimal structural validation; the API is the authority on cron semantics. */
export function isValidCron(cron: string): boolean {
  const parts = cron.trim().split(/\s+/);
  return parts.length === 5 && parts.every((p) => /^[\d*/,\-]+$/.test(p));
}

export interface ScheduleReportDialogProps {
  open: boolean;
  onClose: () => void;
  reports: ReportType[];
  defaultReport: ReportType;
  organizationId: string | null;
  defaultFormat?: ReportFormat;
  defaultPeriodDays?: number;
}

/** Create a recurring report delivered by email / Slack / Teams / webhook channels. */
export function ScheduleReportDialog({ open, onClose, reports, defaultReport, organizationId, defaultFormat = "pdf", defaultPeriodDays = 30 }: ScheduleReportDialogProps) {
  const session = useSession();
  const channels = useNotificationChannels({ enabled: open });
  const create = useCreateReportSchedule();
  const scopeName = organizationId ? (session.organizationName(organizationId) ?? "Organization") : "All organizations";

  const [type, setType] = useState<ReportType>(defaultReport);
  const [name, setName] = useState(`${reportLabel(defaultReport)} — ${scopeName}`);
  const [nameTouched, setNameTouched] = useState(false);
  const [freq, setFreq] = useState<Frequency>("weekly");
  const [time, setTime] = useState("07:00");
  const [weekday, setWeekday] = useState(1);
  const [monthDay, setMonthDay] = useState(1);
  const [custom, setCustom] = useState("0 7 * * 1");
  const [format, setFormat] = useState<ReportFormat>(defaultFormat);
  const [periodDays, setPeriodDays] = useState(defaultPeriodDays);
  const [channelIds, setChannelIds] = useState<string[]>([]);
  const [submitted, setSubmitted] = useState(false);

  const usable = useMemo(
    () => (channels.data ?? []).filter((c) => c.enabled && (c.organizationId === null || c.organizationId === organizationId)),
    [channels.data, organizationId],
  );
  const cron = buildCron(freq, time, weekday, monthDay, custom);
  const cronValid = isValidCron(cron);
  const errors = {
    name: name.trim().length === 0 ? "Name is required" : null,
    cron: cronValid ? null : "Enter a 5-field cron expression (minute hour day month weekday)",
    channels: channelIds.length === 0 ? "Choose at least one delivery channel" : null,
  };
  const valid = !errors.name && !errors.cron && !errors.channels;

  const submit = () => {
    setSubmitted(true);
    if (!valid) return;
    create.mutate(
      { type, name: name.trim(), cron, format, periodDays, organizationId, channelIds, enabled: true },
      { onSuccess: () => setTimeout(onClose, 900) },
    );
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="md"
      title="Schedule report delivery"
      description={`Recurring ${scopeName} report, generated and delivered automatically. Every schedule change is audited.`}
      footer={
        create.isSuccess ? (
          <span className="mr-auto inline-flex items-center gap-1.5 text-sm text-healthy">
            <CircleCheck size={14} aria-hidden /> Schedule created
          </span>
        ) : (
          <>
            {create.isError ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(create.error)}
              </span>
            ) : null}
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={submit} loading={create.isPending} disabled={submitted && !valid}>
              Create schedule
            </Button>
          </>
        )
      }
    >
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Report" required>
            {(p) => (
              <Select
                {...p}
                value={type}
                onChange={(e) => {
                  const next = e.target.value as ReportType;
                  setType(next);
                  if (!nameTouched) setName(`${reportLabel(next)} — ${scopeName}`);
                }}
              >
                {reports.map((r) => (
                  <option key={r} value={r}>
                    {reportLabel(r)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Name" required error={submitted ? errors.name : null}>
            {(p) => (
              <Input
                {...p}
                value={name}
                maxLength={200}
                onChange={(e) => {
                  setName(e.target.value);
                  setNameTouched(true);
                }}
              />
            )}
          </Field>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <Field label="Frequency">
            {(p) => (
              <Select {...p} value={freq} onChange={(e) => setFreq(e.target.value as Frequency)}>
                <option value="daily">Daily</option>
                <option value="weekdays">Weekdays</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="custom">Custom (cron)</option>
              </Select>
            )}
          </Field>
          {freq === "weekly" ? (
            <Field label="Day">
              {(p) => (
                <Select {...p} value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>
                  {WEEKDAYS.map((d, i) => (
                    <option key={d} value={i}>
                      {d}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          ) : freq === "monthly" ? (
            <Field label="Day of month">
              {(p) => (
                <Select {...p} value={monthDay} onChange={(e) => setMonthDay(Number(e.target.value))}>
                  {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
                    <option key={d} value={d}>
                      {d}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          ) : freq === "custom" ? (
            <Field label="Cron (UTC)" error={submitted ? errors.cron : null} className="col-span-2">
              {(p) => <Input {...p} value={custom} onChange={(e) => setCustom(e.target.value)} className="font-mono" />}
            </Field>
          ) : (
            <div />
          )}
          {freq !== "custom" ? (
            <Field label="Time (UTC)">{(p) => <Input {...p} type="time" value={time} onChange={(e) => setTime(e.target.value)} />}</Field>
          ) : null}
        </div>
        <p className="text-xs text-fg-muted">
          {cronValid ? describeCron(cron) : "Invalid schedule"} · <span className="font-mono">{cron || "—"}</span>
        </p>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Format">
            {(p) => (
              <Select {...p} value={format} onChange={(e) => setFormat(e.target.value as ReportFormat)}>
                {REPORT_FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Reporting period">
            {(p) => (
              <Select {...p} value={periodDays} onChange={(e) => setPeriodDays(Number(e.target.value))}>
                {REPORT_PERIODS.map((d) => (
                  <option key={d} value={d}>
                    Last {d} days
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>

        <fieldset className="space-y-1.5">
          <legend className="text-sm font-medium text-fg">
            Deliver to<span className="ml-0.5 text-sev-critical">*</span>
          </legend>
          {channels.isLoading ? (
            <SkeletonText lines={2} />
          ) : usable.length === 0 ? (
            <EmptyState
              compact
              icon={Mail}
              title="No delivery channels configured"
              description="Create an email, Slack, Teams or webhook channel to deliver scheduled reports."
              action={
                <Link to="/soar/channels" className="text-sm font-medium text-primary hover:underline" onClick={onClose}>
                  Configure notification channels
                </Link>
              }
            />
          ) : (
            <ul className="max-h-40 space-y-1 overflow-y-auto rounded border border-line p-2">
              {usable.map((c) => {
                const Icon = CHANNEL_ICONS[c.kind];
                const to = Array.isArray((c.config as { to?: unknown }).to) ? ((c.config as { to: unknown[] }).to.length) : null;
                return (
                  <li key={c.id} className="flex items-center gap-2">
                    <Checkbox
                      label={
                        <span className="inline-flex items-center gap-1.5">
                          <Icon size={13} aria-hidden className="text-fg-muted" />
                          {c.name}
                        </span>
                      }
                      checked={channelIds.includes(c.id)}
                      onChange={(e) => setChannelIds((ids) => (e.target.checked ? [...ids, c.id] : ids.filter((x) => x !== c.id)))}
                    />
                    <Badge size="xs" tone="outline">
                      {c.kind}
                    </Badge>
                    {to !== null ? <span className="text-xs text-fg-subtle">{`${to} recipient${to === 1 ? "" : "s"}`}</span> : null}
                  </li>
                );
              })}
            </ul>
          )}
          {submitted && errors.channels && usable.length > 0 ? <p className="text-xs text-sev-critical">{errors.channels}</p> : null}
        </fieldset>
      </div>
    </Dialog>
  );
}
