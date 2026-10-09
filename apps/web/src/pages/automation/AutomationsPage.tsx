import { CalendarClock, Webhook } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "../../components/PageHeader";
import { Tabs } from "../../components/Tabs";
import { AutomationRulesView } from "./AutomationRulesPage";
import { NotificationChannelsView } from "./NotificationChannelsPage";

type View = "rules" | "channels";

/**
 * /automations — notification automation in one place: rules (event → conditions → channels →
 * template, throttle) and the channels they deliver to (SMTP email, Slack, Teams, webhook, syslog).
 */
export default function AutomationsPage() {
  const [params, setParams] = useSearchParams();
  const view: View = params.get("tab") === "channels" || params.get("create") === "1" ? "channels" : "rules";
  const go = (v: View) => {
    const next = new URLSearchParams(params);
    if (v === "rules") next.delete("tab");
    else next.set("tab", v);
    next.delete("create");
    setParams(next, { replace: true });
  };
  return (
    <div>
      <PageHeader
        title="Automations"
        subtitle="When an event happens and its conditions match, notify the right people — by email, Slack, Teams, webhook or syslog — with throttling and an audit trail."
      >
        <Tabs<View>
          ariaLabel="Automation sections"
          idPrefix="automations"
          value={view}
          onChange={go}
          tabs={[
            { id: "rules", label: "Automation rules", icon: CalendarClock },
            { id: "channels", label: "Notification channels", icon: Webhook },
          ]}
        />
      </PageHeader>
      {view === "rules" ? <AutomationRulesView /> : <NotificationChannelsView />}
    </div>
  );
}
