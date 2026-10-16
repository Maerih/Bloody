import type { QuizResult } from "@bloody/contracts";
import { ArrowLeft, CheckCircle2, Circle, GraduationCap, XCircle } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { errorMessage, isApiError } from "../api/client";
import { useLearnerView, useSubmitQuiz, type LearnerLessonView } from "../api/hooks";
import { Button } from "../components/Button";
import { LogoMark } from "../components/Logo";

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-canvas text-fg">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-4 py-3">
          <span className="inline-flex items-center gap-2 text-lg font-semibold text-heading">
            <LogoMark /> SCIAT
          </span>
          <span className="inline-flex items-center gap-1.5 text-sm text-fg-muted">
            <GraduationCap className="h-4 w-4" aria-hidden /> Security awareness
          </span>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-4 py-6">{children}</main>
    </div>
  );
}

function Lesson({ token, lesson, onBack }: { token: string; lesson: LearnerLessonView; onBack: () => void }) {
  const submit = useSubmitQuiz(token);
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const [result, setResult] = useState<(QuizResult & { completed: boolean }) | null>(null);
  const complete = lesson.quiz.every((q) => answers[q.id] !== undefined);
  const byId = new Map(result?.questions.map((q) => [q.id, q]) ?? []);

  return (
    <article className="space-y-6">
      <button type="button" className="inline-flex items-center gap-1 text-sm text-brand hover:underline" onClick={onBack}>
        <ArrowLeft className="h-4 w-4" aria-hidden /> All lessons
      </button>
      <header>
        <h1 className="text-2xl font-semibold text-heading">{lesson.title}</h1>
        <p className="mt-1 text-fg-muted">{lesson.summary}</p>
      </header>
      {lesson.sections.map((s) => (
        <section key={s.heading} className="space-y-2">
          <h2 className="text-lg font-semibold text-heading">{s.heading}</h2>
          {s.paragraphs.map((p) => (
            <p key={p.slice(0, 40)} className="leading-relaxed">
              {p}
            </p>
          ))}
          {s.tips ? (
            <ul className="space-y-1 rounded border border-line bg-surface p-3">
              {s.tips.map((t) => (
                <li key={t.slice(0, 40)} className="flex gap-2">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-healthy" aria-hidden />
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </section>
      ))}

      <section className="space-y-4 rounded-md border border-line bg-surface p-4" aria-labelledby="quiz-heading">
        <h2 id="quiz-heading" className="text-lg font-semibold text-heading">
          Quick quiz
        </h2>
        {lesson.quiz.map((q, i) => {
          const r = byId.get(q.id);
          return (
            <fieldset key={q.id} className="space-y-1.5">
              <legend className="font-medium">
                {i + 1}. {q.question}
              </legend>
              {q.options.map((o, oi) => (
                <label key={o} className={`flex cursor-pointer items-start gap-2 rounded px-2 py-1 ${r && oi === r.correctOption ? "bg-healthy/10" : ""}`}>
                  <input type="radio" name={q.id} className="mt-1" checked={answers[q.id] === oi} disabled={!!result} onChange={() => setAnswers((a) => ({ ...a, [q.id]: oi }))} />
                  <span>{o}</span>
                </label>
              ))}
              {r ? (
                <p className={`flex gap-1.5 text-sm ${r.correct ? "text-healthy" : "text-sev-critical"}`}>
                  {r.correct ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />}
                  <span>
                    {r.correct ? "Correct. " : "Not quite. "}
                    {r.explain}
                  </span>
                </p>
              ) : null}
            </fieldset>
          );
        })}
        {result ? (
          <div role="status" className={`rounded p-3 ${result.passed ? "bg-healthy/10" : "bg-sev-medium/10"}`}>
            <p className="font-semibold">
              {result.passed ? `Passed with ${result.score}%.` : `You scored ${result.score}%. Read the explanations and try again.`}
            </p>
            {result.completed ? <p className="mt-1">You have finished all your lessons. Thank you!</p> : null}
            <div className="mt-2 flex gap-2">
              {!result.passed ? (
                <Button
                  size="sm"
                  onClick={() => {
                    setResult(null);
                    setAnswers({});
                  }}
                >
                  Try again
                </Button>
              ) : null}
              <Button size="sm" variant={result.passed ? "primary" : "secondary"} onClick={onBack}>
                Back to lessons
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-3">
            <Button variant="primary" disabled={!complete} loading={submit.isPending} onClick={() => submit.mutate({ lesson: lesson.key, answers }, { onSuccess: setResult })}>
              Submit answers
            </Button>
            {submit.error ? (
              <span role="alert" className="text-sm text-sev-critical">
                {errorMessage(submit.error)}
              </span>
            ) : null}
          </div>
        )}
      </section>
    </article>
  );
}

/** Public learner page, opened from the personal link in a training invitation (no account needed). */
export default function LearnPage() {
  const { token = "" } = useParams();
  const view = useLearnerView(token);
  const [open, setOpen] = useState<string | null>(null);

  if (view.isPending) return <Shell>Loading your training…</Shell>;
  if (view.isError) {
    return (
      <Shell>
        <h1 className="text-xl font-semibold text-heading">This training link does not work</h1>
        <p className="mt-2 text-fg-muted">
          {isApiError(view.error) && view.error.status === 404 ? "It may have been replaced by a newer link. Use the most recent invitation, or ask your IT or security team for a new one." : errorMessage(view.error)}
        </p>
      </Shell>
    );
  }
  const v = view.data;
  const lesson = open ? v.lessons.find((l) => l.key === open) : undefined;
  if (lesson) {
    return (
      <Shell>
        <Lesson
          key={lesson.key}
          token={token}
          lesson={lesson}
          onBack={() => {
            setOpen(null);
            window.scrollTo?.(0, 0);
          }}
        />
      </Shell>
    );
  }
  const passed = v.lessons.filter((l) => l.progress?.passed).length;
  return (
    <Shell>
      <p className="text-sm text-fg-muted">{v.organization.name}</p>
      <h1 className="text-2xl font-semibold text-heading">{v.assignment.title}</h1>
      <p className="mt-1">
        Hello {v.learner.name}. {v.assignment.completedAt ? "You have completed this training. Thank you!" : `Read each lesson and pass its short quiz${v.assignment.dueAt ? ` by ${new Date(v.assignment.dueAt).toLocaleDateString()}` : ""}.`}
      </p>
      <div className="mt-4 h-2 overflow-hidden rounded bg-line" role="progressbar" aria-label="Lessons passed" aria-valuemin={0} aria-valuemax={v.lessons.length} aria-valuenow={passed}>
        <div className="h-full bg-healthy" style={{ width: `${(passed / Math.max(1, v.lessons.length)) * 100}%` }} />
      </div>
      <p className="mt-1 text-sm text-fg-muted">
        {passed} of {v.lessons.length} lessons passed
      </p>
      <ul className="mt-4 space-y-2">
        {v.lessons.map((l) => (
          <li key={l.key}>
            <button type="button" className="flex w-full items-center gap-3 rounded-md border border-line bg-surface p-3 text-left hover:border-brand" onClick={() => setOpen(l.key)}>
              {l.progress?.passed ? <CheckCircle2 className="h-5 w-5 shrink-0 text-healthy" aria-label="Passed" /> : <Circle className="h-5 w-5 shrink-0 text-fg-subtle" aria-hidden />}
              <span className="min-w-0 flex-1">
                <span className="block font-medium">{l.title}</span>
                <span className="block text-sm text-fg-muted">
                  {l.minutes} min{l.progress ? ` · best score ${l.progress.bestScore}%` : ""}
                </span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </Shell>
  );
}
