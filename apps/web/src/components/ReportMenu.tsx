import type { ReportFormat, ReportType } from "@bloody/contracts";
import { CalendarClock, Download, FileText, MailPlus } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../api/client";
import { useGenerateReport } from "../api/hooks";
import { useSession } from "../app/session";
import { triggerDownload } from "../lib/download";
import { REPORT_FORMATS, REPORT_PERIODS, reportLabel } from "../lib/reports";
import { Button, type ButtonSize } from "./Button";
import { Field, Select } from "./Form";
import { Popover } from "./Popover";
import { ScheduleReportDialog } from "./ScheduleReportDialog";

export interface ReportMenuProps {
  /** Report types offered here (audience-appropriate). */
  reports: ReportType[];
  defaultReport?: ReportType;
  /** Scope; defaults to the selected organization (null = all organizations). */
  organizationId?: string | null;
  periodDays?: number;
  /** Extra generator parameters, e.g. `{ incidentId }`. */
  parameters?: Record<string, unknown>;
  label?: string;
  size?: ButtonSize;
}

/**
 * "Report" action available on dashboards and detail pages: generate & download now
 * (PDF/HTML/CSV/JSON), or schedule recurring email/Slack/Teams delivery.
 */
export function ReportMenu({ reports, defaultReport, organizationId, periodDays = 30, parameters, label = "Report", size = "sm" }: ReportMenuProps) {
  const session = useSession();
  const scope = organizationId === undefined ? session.organizationId : organizationId;
  const [type, setType] = useState<ReportType>(defaultReport ?? reports[0] ?? "soc_operations");
  const [format, setFormat] = useState<ReportFormat>("pdf");
  const [period, setPeriod] = useState<number>(periodDays);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const generate = useGenerateReport();

  if (!session.can("report:read", scope)) return null;
  const canSchedule = session.can("report:write", scope);

  const download = () => {
    generate.mutate(
      { type, format, organizationId: scope, periodDays: period, ...(parameters ? { parameters } : {}) },
      {
        onSuccess: (res) => {
          const stamp = new Date().toISOString().slice(0, 10);
          triggerDownload(res.blob, res.filename ?? `bloody-${type}-${stamp}.${format}`);
        },
      },
    );
  };

  return (
    <>
      <Popover
        align="end"
        label="Generate report"
        panelClassName="w-72 p-3"
        trigger={(props) => (
          <Button {...props} size={size} icon={FileText}>
            {label}
          </Button>
        )}
      >
        {(close) => (
          <div className="space-y-3">
            <Field label="Report">
              {(p) => (
                <Select {...p} value={type} onChange={(e) => setType(e.target.value as ReportType)}>
                  {reports.map((r) => (
                    <option key={r} value={r}>
                      {reportLabel(r)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Period">
                {(p) => (
                  <Select {...p} value={period} onChange={(e) => setPeriod(Number(e.target.value))}>
                    {REPORT_PERIODS.map((d) => (
                      <option key={d} value={d}>
                        Last {d} days
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
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
            </div>
            <p className="text-xs text-fg-subtle">
              Scope: {scope ? (session.organizationName(scope) ?? "Selected organization") : "All organizations"}
            </p>
            {generate.isError ? (
              <p role="alert" className="text-xs text-sev-critical">
                {errorMessage(generate.error)}
              </p>
            ) : null}
            <div className="flex flex-col gap-1.5">
              <Button variant="primary" icon={Download} loading={generate.isPending} onClick={download}>
                Generate &amp; download
              </Button>
              {canSchedule ? (
                <Button
                  icon={MailPlus}
                  onClick={() => {
                    close();
                    setScheduleOpen(true);
                  }}
                >
                  Schedule email delivery…
                </Button>
              ) : null}
            </div>
            <div className="flex items-center justify-between border-t border-line pt-2 text-xs">
              <Link to="/reports" className="inline-flex items-center gap-1 text-primary hover:underline" onClick={close}>
                <CalendarClock size={12} aria-hidden /> All reports &amp; schedules
              </Link>
            </div>
          </div>
        )}
      </Popover>
      {scheduleOpen ? (
        <ScheduleReportDialog
          open
          onClose={() => setScheduleOpen(false)}
          reports={reports}
          defaultReport={type}
          organizationId={scope}
          defaultFormat={format}
          defaultPeriodDays={period}
        />
      ) : null}
    </>
  );
}
