import { describe, expect, it } from "vitest";
import { AwarenessAssignmentInput, LESSONS, PASS_MARK, gradeQuiz, lessonByKey, lessonForLearner } from "./awareness.js";

describe("security awareness lessons", () => {
  it("has unique lessons with valid, unique quiz questions", () => {
    expect(new Set(LESSONS.map((l) => l.key)).size).toBe(LESSONS.length);
    for (const l of LESSONS) {
      expect(l.quiz.length, l.key).toBeGreaterThanOrEqual(4);
      expect(new Set(l.quiz.map((q) => q.id)).size, l.key).toBe(l.quiz.length);
      for (const q of l.quiz) expect(q.correct >= 0 && q.correct < q.options.length, `${l.key}/${q.id}`).toBe(true);
    }
  });

  it("grades quizzes against the pass mark and never leaks answers to learners", () => {
    const l = lessonByKey("phishing")!;
    const all = Object.fromEntries(l.quiz.map((q) => [q.id, q.correct]));
    expect(gradeQuiz(l, all)).toMatchObject({ score: 100, passed: true });
    const oneWrong = { ...all, q1: (l.quiz[0]!.correct + 1) % l.quiz[0]!.options.length };
    expect(gradeQuiz(l, oneWrong)).toMatchObject({ score: 75, passed: PASS_MARK <= 75 });
    expect(gradeQuiz(l, {})).toMatchObject({ score: 0, passed: false });
    const shown = JSON.stringify(lessonForLearner(l));
    expect(shown).not.toContain("correct");
    expect(shown).not.toContain(l.quiz[0]!.explain);
  });

  it("validates assignments", () => {
    const org = "00000000-0000-4000-8000-000000000001";
    expect(AwarenessAssignmentInput.safeParse({ organizationId: org, title: "Q4 training", lessons: ["phishing", "sim_swap"] }).success).toBe(true);
    expect(AwarenessAssignmentInput.safeParse({ organizationId: org, title: "Q4 training", lessons: ["nope"] }).success).toBe(false);
    expect(AwarenessAssignmentInput.safeParse({ organizationId: org, title: "Q4 training", lessons: [] }).success).toBe(false);
  });
});

describe("phishing templates", () => {
  it("are complete, link a known lesson and never name real brands or ask for passwords on our side", async () => {
    const { PHISH_TEMPLATES, renderPhish, lessonByKey: lesson } = await import("./awareness.js");
    expect(new Set(PHISH_TEMPLATES.map((t) => t.key)).size).toBe(PHISH_TEMPLATES.length);
    for (const t of PHISH_TEMPLATES) {
      expect(lesson(t.lesson), t.key).toBeTruthy();
      expect(t.body, t.key).toContain("{{link}}");
      expect(t.redFlags.length, t.key).toBeGreaterThanOrEqual(2);
      expect(`${t.fromName} ${t.subject} ${t.body}`, t.key).not.toMatch(/microsoft|google|safaricom|m-pesa|mpesa|dhl|fedex|equity|kcb|airtel|amazon|paypal/i);
      const r = renderPhish(t, { name: "Amina", org: "Kilimanjaro Bank", link: "https://x/caught/p_1" });
      expect(r.text).toContain("https://x/caught/p_1");
      expect(r.text).not.toContain("{{");
    }
  });
});

describe("human risk", () => {
  it("is explainable and moves with behaviour", async () => {
    const { humanRisk } = await import("./awareness.js");
    const none = { phishClicks: 0, phishSpotted: 0, completedTraining: 0, overdueTraining: 0, averageScore: null };
    expect(humanRisk(none)).toMatchObject({ score: 35, level: "medium" });
    const good = humanRisk({ phishClicks: 0, phishSpotted: 3, completedTraining: 2, overdueTraining: 0, averageScore: 95 });
    expect(good).toMatchObject({ score: 0, level: "low" });
    const bad = humanRisk({ phishClicks: 2, phishSpotted: 0, completedTraining: 0, overdueTraining: 1, averageScore: 60 });
    expect(bad).toMatchObject({ score: 100, level: "high" });
    expect(bad.reasons[0]).toEqual({ points: 50, text: "Clicked 2 phishing simulations" });
    const one = humanRisk({ ...none, phishClicks: 1, completedTraining: 1 });
    expect(one).toMatchObject({ score: 40, level: "medium" });
    expect(one.reasons.reduce((n, r) => n + r.points, 0)).toBe(40);
  });
});
