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
