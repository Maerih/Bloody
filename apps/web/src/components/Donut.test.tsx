import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Donut, DonutLegend, type DonutSegment } from "./Donut";

const segments: DonutSegment[] = [
  { key: "protected", label: "Protected", value: 3, color: "teal" },
  { key: "unhealthy", label: "Unhealthy", value: 1, color: "red" },
  { key: "unmanaged", label: "Unmanaged", value: 0, color: "purple" },
];

describe("Donut", () => {
  it("draws one arc per non-zero segment with proportional length", () => {
    const { container } = render(<Donut segments={segments} size={100} thickness={20} />);
    expect(screen.getByTestId("donut-arc-protected")).toBeInTheDocument();
    expect(screen.getByTestId("donut-arc-unhealthy")).toBeInTheDocument();
    expect(screen.queryByTestId("donut-arc-unmanaged")).not.toBeInTheDocument();
    const circumference = 2 * Math.PI * 40;
    const dash = Number(screen.getByTestId("donut-arc-protected").getAttribute("stroke-dasharray")!.split(" ")[0]);
    // 3/4 of the ring minus the 1.5px separator gap.
    expect(dash).toBeCloseTo(circumference * 0.75 - 1.5, 3);
    expect(container.querySelector("svg")).toHaveAttribute("aria-label", "Protected: 3 (75%), Unhealthy: 1 (25%), Unmanaged: 0 (0%)");
  });

  it("renders a neutral ring and 'No data' when every value is zero", () => {
    render(<Donut segments={segments.map((s) => ({ ...s, value: 0 }))} />);
    expect(screen.getByRole("img", { name: "No data" })).toBeInTheDocument();
    expect(screen.getByTestId("donut-track")).toBeInTheDocument();
    expect(screen.queryByTestId(/donut-arc-/)).not.toBeInTheDocument();
  });

  it("uses a single full arc without a gap for one segment", () => {
    render(<Donut segments={[{ key: "only", label: "Only", value: 5, color: "teal" }]} size={100} thickness={20} />);
    const dash = Number(screen.getByTestId("donut-arc-only").getAttribute("stroke-dasharray")!.split(" ")[0]);
    expect(dash).toBeCloseTo(2 * Math.PI * 40, 3);
  });

  it("legend lists every segment with counts and drill-down links", () => {
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <DonutLegend title="Status" segments={[{ ...segments[0]!, href: "/agents?status=protected" }, segments[1]!]} />
      </MemoryRouter>,
    );
    expect(screen.getByText("Status")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Protected/ })).toHaveAttribute("href", "/agents?status=protected");
    expect(screen.getByText("Unhealthy").closest("li")).toHaveTextContent("1");
  });
});
