import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { DataTable, compareCells, type DataTableColumn } from "./DataTable";

interface Row {
  id: string;
  name: string;
  severity: string;
  score: number | null;
}

const rows: Row[] = Array.from({ length: 30 }, (_, i) => ({
  id: `r${i}`,
  name: `Host ${String(i).padStart(2, "0")}`,
  severity: i % 3 === 0 ? "critical" : "low",
  score: i === 5 ? null : i,
}));

const columns: DataTableColumn<Row>[] = [
  { id: "name", header: "Name", accessor: (r) => r.name },
  { id: "severity", header: "Severity", accessor: (r) => r.severity, filter: { kind: "select", options: [{ value: "critical", label: "Critical" }, { value: "low", label: "Low" }] } },
  { id: "score", header: "Score", accessor: (r) => r.score, align: "right" },
];

function renderTable(props: Partial<Parameters<typeof DataTable<Row>>[0]> = {}) {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <DataTable columns={columns} rows={rows} getRowId={(r) => r.id} {...props} />
    </MemoryRouter>,
  );
}

const bodyRows = () => screen.getAllByRole("row").slice(1);

describe("DataTable", () => {
  it("paginates 25 rows per page by default", () => {
    renderTable();
    expect(bodyRows()).toHaveLength(25);
    expect(screen.getByText("1–25 of 30")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(bodyRows()).toHaveLength(5);
  });

  it("sorts ascending then descending with nulls last", () => {
    renderTable();
    fireEvent.click(screen.getByRole("button", { name: /Score/ }));
    expect(within(bodyRows()[0]!).getByText("0")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Score/ }));
    expect(within(bodyRows()[0]!).getByText("29")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Score/ })).toHaveAttribute("aria-sort", "descending");
  });

  it("filters with global search and column filters", () => {
    renderTable();
    fireEvent.change(screen.getByLabelText("Search table"), { target: { value: "host 1" } });
    expect(bodyRows()).toHaveLength(10);
    fireEvent.change(screen.getByLabelText("Search table"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: /Filters/ }));
    fireEvent.change(screen.getByLabelText("Filter Severity"), { target: { value: "critical" } });
    expect(bodyRows()).toHaveLength(10);
    expect(screen.getByText(/filtered from 30/)).toBeInTheDocument();
  });

  it("saves and re-applies views in localStorage", () => {
    renderTable({ savedViewsKey: "test" });
    fireEvent.change(screen.getByLabelText("Search table"), { target: { value: "host 2" } });
    fireEvent.click(screen.getByRole("button", { name: "Views" }));
    fireEvent.change(screen.getByLabelText("View name"), { target: { value: "Twenties" } });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));
    expect(JSON.parse(localStorage.getItem("bloody.views.test")!)[0].name).toBe("Twenties");
    // The trigger now shows the active view; the panel is still open. Reset to default…
    expect(screen.getByRole("button", { name: "Twenties", expanded: true })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Default view" }));
    expect(bodyRows()).toHaveLength(25);
    fireEvent.click(screen.getByRole("button", { name: "Views" }));
    fireEvent.click(screen.getByRole("button", { name: "Twenties" }));
    expect(bodyRows()).toHaveLength(10);
  });

  it("calls onRowClick with mouse and keyboard", () => {
    const onRowClick = vi.fn();
    renderTable({ onRowClick });
    fireEvent.click(bodyRows()[0]!);
    fireEvent.keyDown(bodyRows()[1]!, { key: "Enter" });
    expect(onRowClick).toHaveBeenNthCalledWith(1, rows[0]);
    expect(onRowClick).toHaveBeenNthCalledWith(2, rows[1]);
  });

  it("shows the provided empty state when there are no rows", () => {
    renderTable({ rows: [], emptyState: <p>Nothing to triage</p> });
    expect(screen.getByText("Nothing to triage")).toBeInTheDocument();
  });

  it("compareCells orders numbers, strings and nulls", () => {
    expect(compareCells(2, 10)).toBeLessThan(0);
    expect(compareCells("host 2", "host 10")).toBeLessThan(0);
    expect(compareCells(null, 1)).toBeGreaterThan(0);
  });
});
