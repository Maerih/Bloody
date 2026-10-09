import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { clauseIsComplete, parseQuery, serializeClause, serializeQuery, type QueryClause } from "../lib/eventQuery";
import { QueryBuilder } from "./QueryBuilder";

describe("event query syntax", () => {
  it("serializes chips into Bloody query syntax", () => {
    const clauses: QueryClause[] = [
      { field: "process.name", op: "eq", value: "powershell.exe" },
      { field: "user.name", op: "neq", value: "svc backup" },
      { field: "process.commandLine", op: "contains", value: "-enc" },
      { field: "network.dstPort", op: "gte", value: "1024" },
      { field: "severity", op: "in", value: "high, critical" },
      { field: "file.sha256", op: "exists", value: "" },
    ];
    expect(clauses.map(serializeClause)).toEqual([
      "process.name:powershell.exe",
      'NOT user.name:"svc backup"',
      "process.commandLine:*-enc*",
      "network.dstPort:>=1024",
      "severity:(high OR critical)",
      "file.sha256:*",
    ]);
    expect(serializeQuery(clauses.slice(0, 2), "mimikatz")).toBe('process.name:powershell.exe AND NOT user.name:"svc backup" AND mimikatz');
  });

  it("round-trips builder queries through parseQuery", () => {
    const clauses: QueryClause[] = [
      { field: "category", op: "eq", value: "process" },
      { field: "process.commandLine", op: "contains", value: "lsass dump" },
      { field: "risk", op: "lt", value: "50" },
      { field: "severity", op: "in", value: "high, critical" },
      { field: "message", op: "neq", value: 'quoted "value"' },
    ];
    const parsed = parseQuery(serializeQuery(clauses, "free text"));
    expect(parsed).toEqual({ clauses, freeText: "free text" });
  });

  it("refuses constructs the chips cannot express (top-level OR, groups) so they stay raw", () => {
    expect(parseQuery("process.name:cmd.exe OR process.name:powershell.exe")).toBeNull();
    expect(parseQuery("(category:dns AND network.dnsQuery:*evil*)")).toBeNull();
    expect(parseQuery("AND category:dns")).toBeNull();
    expect(parseQuery("")).toEqual({ clauses: [], freeText: "" });
  });

  it("only treats complete clauses as addable", () => {
    expect(clauseIsComplete({ field: "network.dstPort", op: "gt", value: "abc" })).toBe(false);
    expect(clauseIsComplete({ field: "bad field", op: "eq", value: "x" })).toBe(false);
    expect(clauseIsComplete({ field: "severity", op: "in", value: " , " })).toBe(false);
    expect(clauseIsComplete({ field: "file.sha256", op: "exists", value: "" })).toBe(true);
  });
});

describe("QueryBuilder", () => {
  it("adds field / operator / value chips, previews the query and submits it", () => {
    const onSubmit = vi.fn();
    render(<QueryBuilder value="" onSubmit={onSubmit} />);
    const form = screen.getByTestId("query-builder");
    fireEvent.change(within(form).getByLabelText("Field"), { target: { value: "process.name" } });
    fireEvent.change(within(form).getByLabelText("Operator"), { target: { value: "eq" } });
    fireEvent.change(within(form).getByLabelText("Value"), { target: { value: "powershell.exe" } });
    fireEvent.click(within(form).getByRole("button", { name: "Add condition" }));
    expect(within(form).getAllByTestId("query-chip")).toHaveLength(1);

    // Numeric fields offer range operators; Enter in the value input adds the chip.
    fireEvent.change(within(form).getByLabelText("Field"), { target: { value: "network.dstPort" } });
    fireEvent.change(within(form).getByLabelText("Operator"), { target: { value: "gte" } });
    const value = within(form).getByLabelText("Value");
    fireEvent.change(value, { target: { value: "1024" } });
    fireEvent.keyDown(value, { key: "Enter" });
    expect(within(form).getAllByTestId("query-chip")).toHaveLength(2);

    fireEvent.change(within(form).getByLabelText("Free text"), { target: { value: "mimikatz" } });
    expect(within(form).getByTestId("query-preview")).toHaveTextContent("Query: process.name:powershell.exe AND network.dstPort:>=1024 AND mimikatz");
    fireEvent.click(within(form).getByRole("button", { name: "Search" }));
    expect(onSubmit).toHaveBeenCalledWith("process.name:powershell.exe AND network.dstPort:>=1024 AND mimikatz");
  });

  it("offers enum values as a select and includes a filled-in draft on submit", () => {
    const onSubmit = vi.fn();
    render(<QueryBuilder value="" onSubmit={onSubmit} />);
    const form = screen.getByTestId("query-builder");
    fireEvent.change(within(form).getByLabelText("Field"), { target: { value: "category" } });
    const select = within(form).getByLabelText("Value");
    expect(select.tagName).toBe("SELECT");
    fireEvent.change(select, { target: { value: "dns" } });
    fireEvent.click(within(form).getByRole("button", { name: "Search" }));
    expect(onSubmit).toHaveBeenCalledWith("category:dns");
    expect(within(form).getAllByTestId("query-chip")).toHaveLength(1);
  });

  it("removes chips and parses an incoming query (saved search / pivot) into chips", () => {
    const onSubmit = vi.fn();
    render(<QueryBuilder value='category:authentication AND outcome:failure AND NOT identity.sourceIp:"10.0.0.1"' onSubmit={onSubmit} />);
    const form = screen.getByTestId("query-builder");
    expect(within(form).getAllByTestId("query-chip")).toHaveLength(3);
    fireEvent.click(within(form).getByRole("button", { name: "Remove condition outcome:failure" }));
    expect(within(form).getAllByTestId("query-chip")).toHaveLength(2);
    expect(within(form).getByTestId("query-preview")).toHaveTextContent('Query: category:authentication AND NOT identity.sourceIp:10.0.0.1');
  });

  it("switches to raw mode for OR queries and refuses to switch back to chips", () => {
    const onSubmit = vi.fn();
    render(<QueryBuilder value="category:dns" onSubmit={onSubmit} />);
    const form = screen.getByTestId("query-builder");
    fireEvent.click(within(form).getByRole("tab", { name: /Raw query/ }));
    const raw = within(form).getByLabelText("Raw query");
    expect(raw).toHaveValue("category:dns");
    fireEvent.change(raw, { target: { value: "process.name:cmd.exe OR process.name:powershell.exe" } });
    fireEvent.click(within(form).getByRole("tab", { name: /Builder/ }));
    expect(within(form).getByRole("alert")).toHaveTextContent(/can't show as chips/);
    expect(within(form).getByRole("tab", { name: /Raw query/ })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(raw, { key: "Enter", ctrlKey: true });
    expect(onSubmit).toHaveBeenCalledWith("process.name:cmd.exe OR process.name:powershell.exe");
  });
});
