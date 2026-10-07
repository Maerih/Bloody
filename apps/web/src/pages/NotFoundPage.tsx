import { SearchX } from "lucide-react";
import { useLocation } from "react-router-dom";
import { ButtonLink } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function NotFoundPage() {
  useDocumentTitle("Not found");
  const location = useLocation();
  return (
    <div className="rounded border border-line bg-surface shadow-card">
      <EmptyState
        icon={SearchX}
        title="Page not found"
        description={
          <>
            Nothing lives at <span className="font-mono">{location.pathname}</span>. Use ⌘K / Ctrl+K to search.
          </>
        }
        action={<ButtonLink to="/" variant="primary" size="sm">Back to Command Center</ButtonLink>}
      />
    </div>
  );
}
