import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { SeverityBar } from "./SeverityBar";

describe("SeverityBar", () => {
  it("renders the count, label and endpoint/identity sub-counts", () => {
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <SeverityBar level="critical" count={3} endpointCount={2} identityCount={1} href="/incidents?severity=critical" />
      </MemoryRouter>,
    );
    const link = screen.getByRole("link", { name: "3 Critical incidents, 2 endpoint, 1 identity" });
    expect(link).toHaveAttribute("href", "/incidents?severity=critical");
    expect(screen.getByTestId("severity-count-critical")).toHaveTextContent("3");
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByTitle("Incidents involving endpoints")).toHaveTextContent("2");
    expect(screen.getByTitle("Incidents involving identities")).toHaveTextContent("1");
  });

  it("omits sub-counts when they are unknown instead of showing zeros", () => {
    render(<SeverityBar level="high" count={5} />);
    expect(screen.getByRole("group", { name: "5 High incidents" })).toBeInTheDocument();
    expect(screen.queryByTitle("Incidents involving endpoints")).not.toBeInTheDocument();
  });

  it("supports the combined low/medium bar with a custom label", () => {
    render(<SeverityBar level="low_medium" label="Low / Medium" count={1234} endpointCount={0} identityCount={0} />);
    expect(screen.getByTestId("severity-count-low_medium")).toHaveTextContent("1,234");
    expect(screen.getByText("Low / Medium")).toBeInTheDocument();
  });
});
