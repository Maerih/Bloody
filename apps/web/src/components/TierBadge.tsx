import type { AiToolTier } from "@bloody/contracts";
import { TOOL_TIER_META } from "../lib/aiProviders";
import { Badge } from "./Badge";

/** AI tool permission tier: READ / INVESTIGATE / RECOMMEND / REQUIRE APPROVAL / EXECUTE. */
export function TierBadge({ tier, size = "xs" }: { tier: AiToolTier; size?: "xs" | "sm" }) {
  const meta = TOOL_TIER_META[tier];
  return (
    <Badge tone={meta.tone} size={size} title={meta.description} className="font-mono tracking-wide">
      {meta.label}
    </Badge>
  );
}
