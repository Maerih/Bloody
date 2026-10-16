import { LESSONS } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderApp, renderWithSession } from "../../test/utils";
import { AwarenessOverviewSection } from "./AwarenessPage";

const NOW = new Date().toISOString();
const lessons = { passMark: 75, items: LESSONS.map(({ key, title, minutes, summary, quiz }) => ({ key, title, minutes, summary, questions: quiz.length })) };
const overview = {
  organizationId: ORG_A,
  canEmail: true,
  summary: { learners: 2, enrolments: 2, completed: 1, completionRate: 50, overdue: 0, averageScore: 88 },
  learners: [],
  assignments: [
    {
      id: "00000000-0000-4000-8000-0000000000c1",
      title: "Q4 phishing & fraud",
      lessons: ["phishing", "payment_fraud"],
      dueAt: null,
      createdAt: NOW,
      enrolments: [
        { id: "e1", learnerId: "l1", learnerName: "Amina Mushi", learnerEmail: "amina@kb.example", invitedAt: NOW, completedAt: NOW, lessonsPassed: 2, averageScore: 88 },
        { id: "e2", learnerId: "l2", learnerName: "Joseph Mrema", learnerEmail: "joseph@kb.example", invitedAt: null, completedAt: null, lessonsPassed: 0, averageScore: null },
      ],
    },
  ],
};

describe("Security Awareness Training (admin)", () => {
  it("shows completion, assigns lessons and hands out the personal links", async () => {
    const { calls } = mockApi({
      "/awareness/overview": overview,
      "/awareness/lessons": lessons,
      "POST /awareness/assignments": { id: "a2", links: [{ enrolmentId: "e9", name: "Amina Mushi", email: "amina@kb.example", url: "https://sciat.example/learn/l_abc" }] },
    });
    renderWithSession(<AwarenessOverviewSection />);
    expect(await screen.findByText("Q4 phishing & fraud")).toBeInTheDocument();
    expect(screen.getByText("1 of 2")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Assign training" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Title"), { target: { value: "SIM swap awareness" } });
    fireEvent.click(await within(dialog).findByLabelText("SIM-swap and mobile-money fraud"));
    fireEvent.click(within(dialog).getByRole("button", { name: /^Assign/ }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ organizationId: ORG_A, title: "SIM swap awareness", lessons: ["sim_swap"] }));
    expect(await screen.findByText("https://sciat.example/learn/l_abc")).toBeInTheDocument();
  });
});

describe("learner page (public)", () => {
  const view = {
    learner: { name: "Amina Mushi" },
    organization: { name: "Kilimanjaro Bank" },
    assignment: { title: "Q4 phishing & fraud", dueAt: null, completedAt: null },
    lessons: LESSONS.filter((l) => l.key === "phishing").map((l) => ({ ...l, quiz: l.quiz.map(({ id, question, options }) => ({ id, question, options })), progress: null })),
  };
  it("reads a lesson and submits the quiz without signing in", async () => {
    const { calls } = mockApi({
      "/learn/l_tok": view,
      "POST /learn/l_tok/lessons/phishing/quiz": { score: 100, passed: true, completed: true, questions: LESSONS[0]!.quiz.map((q) => ({ id: q.id, correct: true, correctOption: q.correct, explain: q.explain })) },
    });
    renderApp("/learn/l_tok");
    expect(await screen.findByText("Hello Amina Mushi.", { exact: false })).toBeInTheDocument();
    fireEvent.click(screen.getByText("Spotting phishing emails and messages"));
    expect(await screen.findByText("The warning signs")).toBeInTheDocument();
    const submit = screen.getByRole("button", { name: "Submit answers" });
    expect(submit).toBeDisabled();
    for (const q of LESSONS[0]!.quiz) fireEvent.click(within(screen.getByRole("group", { name: new RegExp(q.question.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) })).getAllByRole("radio")[q.correct]!);
    fireEvent.click(submit);
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ answers: Object.fromEntries(LESSONS[0]!.quiz.map((q) => [q.id, q.correct])) }));
    expect(await screen.findByText("Passed with 100%.")).toBeInTheDocument();
    expect(screen.getByText(/finished all your lessons/)).toBeInTheDocument();
  });

  it("explains a link that no longer works", async () => {
    mockApi({ "/learn/l_old": { status: 404, body: { error: { code: "not_found", message: "Training link not found" } } } });
    renderApp("/learn/l_old");
    expect(await screen.findByText("This training link does not work")).toBeInTheDocument();
  });
});
