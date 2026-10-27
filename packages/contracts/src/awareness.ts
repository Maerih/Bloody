import { z } from "zod";

/**
 * Security Awareness Training (proprietary SCIAT content, (c) SCIAT AFRICA). Short lessons for the
 * staff of each customer organization, each ending in a quiz. An MSSP assigns lessons to the
 * organization's people; learners open a personal link (no account needed), read, and pass the
 * quiz; the MSSP tracks completion and scores per organization.
 */

export interface LessonSection {
  heading: string;
  paragraphs: string[];
  /** Short do / don't list shown as a callout. */
  tips?: string[];
}

export interface QuizQuestion {
  id: string;
  question: string;
  options: string[];
  /** Index of the correct option (never sent to learners before they answer). */
  correct: number;
  explain: string;
}

export interface Lesson {
  key: string;
  title: string;
  minutes: number;
  summary: string;
  sections: LessonSection[];
  quiz: QuizQuestion[];
}

export const PASS_MARK = 75;

export const LESSONS: Lesson[] = [
  {
    key: "phishing",
    title: "Spotting phishing emails and messages",
    minutes: 6,
    summary: "How attackers trick people into clicking, signing in or opening attachments, and the few checks that catch almost every attempt.",
    sections: [
      {
        heading: "What phishing is",
        paragraphs: [
          "Phishing is a message that pretends to come from someone you trust (your bank, Microsoft, KRA, a courier, your own IT team or your manager) to make you click a link, enter a password, open an attachment or send money.",
          "It arrives by email, SMS, WhatsApp, LinkedIn and phone calls. Most cyber attacks on organizations start with one convincing message to one person.",
        ],
      },
      {
        heading: "The warning signs",
        paragraphs: ["Attackers rely on pressure and on you not looking closely. Slow down and check:"],
        tips: [
          "Urgency or fear: “your account will be closed today”, “payment overdue”, “final notice”.",
          "The sender address does not match the name, or is a look-alike domain (micros0ft-support.com, kilimanjaro-bank.co instead of .co.tz).",
          "A link whose real address (hover or long-press to see it) goes somewhere unexpected.",
          "An unexpected attachment, especially .zip, .html, .iso, or an Office file asking you to “enable content”.",
          "A sign-in page reached from a link: always open the service yourself instead.",
          "Requests that break normal process: gift cards, new bank details, secrecy.",
        ],
      },
      {
        heading: "What to do",
        paragraphs: [
          "Do not click, reply or forward it to colleagues. Report it using your organization's report button or to IT, then delete it.",
          "If you already clicked or typed a password, tell IT immediately. Changing the password within minutes often stops the attack; waiting until tomorrow often does not.",
        ],
      },
    ],
    quiz: [
      { id: "q1", question: "An email from “Microsoft 365” says your mailbox is full and links to a sign-in page. What should you do?", options: ["Sign in quickly so mail keeps working", "Open Outlook or office.com yourself and check, and report the email", "Forward it to colleagues to warn them", "Reply asking if it is real"], correct: 1, explain: "Never sign in from a link in a message. Open the service yourself; if there is a real problem you will see it there." },
      { id: "q2", question: "Which sender address is most suspicious for a message from Equity Bank?", options: ["alerts@equitybank.co.ke", "no-reply@equitybank.co.ke", "security@equity-bank-verify.com", "notifications@equitybank.co.ke"], correct: 2, explain: "Look-alike domains that add words such as “verify” or “secure” are a classic phishing trick." },
      { id: "q3", question: "You clicked a link and typed your password before realising it was fake. What now?", options: ["Nothing, it is probably fine", "Wait to see if anything strange happens", "Tell IT straight away and change the password", "Delete the email so nobody knows"], correct: 2, explain: "Speed matters: reporting within minutes lets IT block the attacker before they use your account." },
      { id: "q4", question: "Which attachment is the biggest red flag in an unexpected invoice email?", options: ["A PDF from a supplier you know, expected this week", "A .zip file containing “Invoice.html”", "A photo of a receipt you asked for", "A calendar invite from a colleague"], correct: 1, explain: "Unexpected archives and HTML attachments are common ways to deliver malware or fake sign-in pages." },
    ],
  },
  {
    key: "payment_fraud",
    title: "Payment fraud and business email compromise",
    minutes: 6,
    summary: "Fake invoices, changed bank details and urgent requests from “the boss”: the attacks that cost organizations the most money.",
    sections: [
      {
        heading: "How it works",
        paragraphs: [
          "In business email compromise (BEC) an attacker takes over, or imitates, the email of a supplier, customer or executive. They watch real conversations, then step in at the right moment: “please note our bank details have changed” or “I need this payment made today, I am in a meeting”.",
          "No malware is involved, so antivirus cannot stop it. Only a good process and an alert person can.",
        ],
      },
      {
        heading: "The rules that stop it",
        paragraphs: ["Make these habits, even when the request looks completely genuine:"],
        tips: [
          "Never change bank, M-Pesa till or paybill details because of an email. Confirm by calling a number you already have on file, not one in the message.",
          "Treat urgency and secrecy from executives as a warning sign, not a reason to skip checks.",
          "Follow the two-person approval process for payments, every time.",
          "Watch for small changes in addresses and reply-to fields (ceo@yourcompany.co vs ceo@yourcompany.com).",
          "Gift cards and airtime are never a normal business payment.",
        ],
      },
      {
        heading: "If money has been sent",
        paragraphs: ["Call your bank or mobile-money provider immediately and ask for a recall, then tell IT and management. Recovery is often possible in the first hours and rarely after days."],
      },
    ],
    quiz: [
      { id: "q1", question: "A long-standing supplier emails new bank details for this month's invoice. What do you do?", options: ["Update the details; the email thread is genuine", "Call the supplier on the number already in your records to confirm", "Reply to the email asking them to confirm", "Pay half to the new account to be safe"], correct: 1, explain: "The email account itself may be compromised, so replies go to the attacker. Confirm through a separate, known channel." },
      { id: "q2", question: "The CEO emails: “Buy 10 Safaricom vouchers and send me the codes, it's urgent and confidential.” This is:", options: ["Normal for an urgent client gift", "A typical fraud pattern to report", "Fine if the email address looks right", "Fine if the amount is small"], correct: 1, explain: "Vouchers, gift cards, urgency and secrecy together are a textbook BEC scam." },
      { id: "q3", question: "Why can't antivirus stop most payment fraud?", options: ["It is too old", "There is no malware, only convincing messages", "Attackers switch it off", "It only works on servers"], correct: 1, explain: "BEC uses ordinary emails; the defence is process and verification." },
      { id: "q4", question: "You realise a payment went to a fraudster an hour ago. First step?", options: ["Wait for the supplier to complain", "Call the bank / mobile-money provider to request a recall, then report internally", "Delete the emails", "Email the fraudster asking for the money back"], correct: 1, explain: "The first hours give the best chance of stopping or recalling the transfer." },
    ],
  },
  {
    key: "passwords_mfa",
    title: "Passwords, password managers and MFA",
    minutes: 5,
    summary: "Why reused passwords get accounts taken over, how a password manager fixes it, and how attackers try to beat MFA.",
    sections: [
      {
        heading: "Reuse is the real problem",
        paragraphs: [
          "Websites are breached every day and their password lists are sold. Attackers then try those email-and-password pairs on email, banking and company systems. If you reuse a password, one breach anywhere opens everything.",
          "A long passphrase (four or more random words) is stronger and easier to remember than a short complex password.",
        ],
        tips: ["Use a different password for every account.", "Let a password manager create and remember them.", "Never share passwords, not even with IT. IT never needs your password."],
      },
      {
        heading: "Multi-factor authentication (MFA)",
        paragraphs: [
          "MFA adds a second proof (an app prompt, a code or a security key) so a stolen password alone is not enough. Turn it on everywhere it is offered, starting with email.",
          "Attackers know this, so they try to trick you into approving their sign-in: they send prompt after prompt hoping you tap Approve to make it stop (“MFA fatigue”), or they call pretending to be IT and ask for the code.",
        ],
        tips: ["Only approve a prompt you started yourself, seconds ago.", "If prompts appear that you did not trigger, deny them and tell IT: someone has your password.", "Never read an MFA code to anyone."],
      },
    ],
    quiz: [
      { id: "q1", question: "Your phone shows repeated MFA approval prompts while you are in a meeting. What does it mean?", options: ["A system glitch, approve one to stop them", "Someone has your password and is trying to sign in; deny and tell IT", "Your phone needs an update", "IT is testing the system"], correct: 1, explain: "Unexpected prompts mean your password is known. Deny them and get the password changed." },
      { id: "q2", question: "Which is the strongest choice?", options: ["The same complex password everywhere", "A different random password per account in a password manager", "Your child's name and birth year", "A password written under the keyboard"], correct: 1, explain: "Unique passwords stop one breach from unlocking your other accounts." },
      { id: "q3", question: "Someone from “IT support” calls and asks for the code just sent to your phone. You should:", options: ["Read it out, IT needs it", "Refuse, hang up and report the call", "Send it by WhatsApp instead", "Give only half the code"], correct: 1, explain: "Real IT never asks for your codes or passwords." },
      { id: "q4", question: "Where should MFA be turned on first?", options: ["Your email account", "A news website", "A game", "Nowhere, it is inconvenient"], correct: 0, explain: "Email resets every other password, so it is the most valuable account to protect." },
    ],
  },
  {
    key: "sim_swap",
    title: "SIM-swap and mobile-money fraud",
    minutes: 4,
    summary: "How fraudsters take over phone numbers and mobile-money accounts, and the warning signs to act on immediately.",
    sections: [
      {
        heading: "How a SIM swap works",
        paragraphs: [
          "The fraudster collects your personal details (from social media, a leaked list or a convincing call), then persuades or bribes someone at a mobile operator to move your number to a SIM card they hold. From that moment they receive your calls, SMS codes and M-Pesa or other mobile-money PIN resets.",
          "Many sign-ins and bank transfers are protected only by SMS codes, so a stolen number can empty accounts within an hour.",
        ],
      },
      {
        heading: "Protect yourself",
        paragraphs: ["Small habits make you a much harder target:"],
        tips: [
          "If your phone suddenly loses network for no reason, call your operator from another phone at once.",
          "Never share your mobile-money PIN, ID number and date of birth with callers, even if they claim to be from the operator or bank.",
          "Prefer an authenticator app over SMS codes for work and email accounts.",
          "Be careful what you post: ID photos, birthdays and phone numbers help fraudsters.",
          "“Wrong transaction, please send it back” messages are a common scam: check your actual balance first.",
        ],
      },
    ],
    quiz: [
      { id: "q1", question: "Your phone shows “No service” for an hour while others nearby have signal. What should you do?", options: ["Restart it tomorrow", "Call your operator from another phone immediately", "Ignore it", "Post about it on social media"], correct: 1, explain: "Unexpected loss of service can be a SIM swap in progress; minutes matter." },
      { id: "q2", question: "A caller from “Safaricom” asks for your M-Pesa PIN to fix a problem. This is:", options: ["Normal verification", "A scam: operators never ask for your PIN", "Fine if they know your name", "Fine if they call from 100"], correct: 1, explain: "No genuine operator or bank ever asks for your PIN." },
      { id: "q3", question: "You receive an SMS: “I sent you KSh 3,000 by mistake, please send it back.” First:", options: ["Send it back quickly", "Check your actual mobile-money balance and statement", "Call the number back and send half", "Forward the SMS to friends"], correct: 1, explain: "Fake “sent by mistake” messages are common; verify in your real balance before doing anything." },
      { id: "q4", question: "Which second factor is safest against SIM swap?", options: ["SMS code", "Authenticator app or security key", "Email to the same phone", "No second factor"], correct: 1, explain: "Codes in an app or a security key do not move with your phone number." },
    ],
  },
  {
    key: "ransomware_reporting",
    title: "Ransomware and reporting incidents fast",
    minutes: 5,
    summary: "What ransomware does, how it gets in, and why reporting something odd within minutes is the most valuable thing you can do.",
    sections: [
      {
        heading: "What ransomware is",
        paragraphs: [
          "Ransomware encrypts an organization's files and systems and demands payment. Modern gangs also steal data first and threaten to publish it. Recovery can take weeks and affects customers, salaries and reputation.",
          "It usually starts small: a phishing email, a stolen password, a fake software download, or a remote-access tool installed by someone who believed a “support” caller.",
        ],
      },
      {
        heading: "Report early, report everything",
        paragraphs: [
          "Attackers often spend days inside a network before encrypting anything. Every early report gives the security team a chance to stop them. You will never be in trouble for reporting something that turns out to be harmless.",
        ],
        tips: [
          "Report: strange pop-ups, files you cannot open, new programs you did not install, your mouse moving by itself, colleagues receiving odd emails “from you”.",
          "If you suspect infection, disconnect from the network (unplug the cable / turn off Wi-Fi) but leave the computer on, and call IT.",
          "Never let an unexpected caller install AnyDesk, TeamViewer or similar on your computer.",
        ],
      },
    ],
    quiz: [
      { id: "q1", question: "Files on your shared drive suddenly have strange extensions and won't open. What do you do?", options: ["Keep working on other files", "Disconnect from the network, leave the PC on, call IT", "Turn the computer off and go home", "Try renaming the files"], correct: 1, explain: "Disconnecting limits the spread; keeping the machine on preserves evidence for responders." },
      { id: "q2", question: "A caller says they are from your bank's tech support and asks you to install AnyDesk. You should:", options: ["Install it, they sound professional", "Refuse and report the call", "Install it but watch what they do", "Ask for their staff number then install it"], correct: 1, explain: "Remote-access tools give full control of your computer; this is a common start of fraud and ransomware." },
      { id: "q3", question: "Why does reporting quickly matter so much?", options: ["It does not, attacks happen instantly", "Attackers are often inside for days before encrypting; early reports let the team stop them", "Only so IT can blame someone", "Reports are only needed for insurance"], correct: 1, explain: "The time between first access and encryption is the defenders' window." },
      { id: "q4", question: "You reported a suspicious email that turned out to be genuine. Was that right?", options: ["No, it wasted time", "Yes, reporting harmless things is always better than missing a real attack", "Only if your manager approved", "Only for emails from outside"], correct: 1, explain: "Security teams would rather check ten harmless reports than miss one real attack." },
    ],
  },
  {
    key: "safe_devices",
    title: "Safe browsing, downloads and devices",
    minutes: 5,
    summary: "Fake downloads, public Wi-Fi, USB drives and updates: everyday habits that keep your computer and phone safe.",
    sections: [
      {
        heading: "Downloads and software",
        paragraphs: ["Attackers buy search ads and create look-alike sites that offer popular software with malware inside. Cracked software and “free activators” are a favourite way to infect computers."],
        tips: ["Install software only from the official vendor site or your company's software centre.", "Never install cracked or “activated” software.", "If a site says your computer is infected and gives a number to call, close it: it is a scam."],
      },
      {
        heading: "Devices and networks",
        paragraphs: ["Your laptop and phone carry company email, files and passwords. Treat them like keys to the office."],
        tips: [
          "Install updates promptly and restart when asked: most attacks use flaws that already have fixes.",
          "Lock your screen every time you step away (Windows key + L, or Ctrl + Cmd + Q on Mac).",
          "On public Wi-Fi, use the company VPN or your phone's hotspot for work.",
          "Do not plug in USB drives you found or were given unexpectedly.",
          "Report a lost or stolen device to IT immediately so it can be locked and wiped.",
        ],
      },
    ],
    quiz: [
      { id: "q1", question: "A pop-up says “Your computer is infected! Call Microsoft at this number.” It is:", options: ["A real Microsoft warning", "A tech-support scam; close the page", "Your antivirus", "Safe if the number is local"], correct: 1, explain: "Microsoft never shows phone numbers in browser warnings. Close the tab; if it won't close, restart the browser." },
      { id: "q2", question: "Where should you download work software from?", options: ["The first search result", "The official vendor site or company software centre", "A file-sharing site", "A link in a WhatsApp group"], correct: 1, explain: "Search ads and look-alike sites often host infected installers." },
      { id: "q3", question: "You find a USB drive labelled “Salaries 2026” in the car park. You should:", options: ["Plug it in to find the owner", "Hand it to IT without plugging it in", "Take it home", "Plug it into a colleague's computer"], correct: 1, explain: "Dropped USB drives are a known way to deliver malware; let IT handle it." },
      { id: "q4", question: "Your laptop asks to restart to finish updates. Best response?", options: ["Postpone it for weeks", "Save your work and restart today", "Turn off automatic updates", "Unplug the network cable"], correct: 1, explain: "Updates close holes attackers are actively using; delaying them leaves you exposed." },
    ],
  },
  {
    key: "data_protection",
    title: "Handling personal and sensitive data",
    minutes: 5,
    summary: "What counts as personal data, how to share it safely, and what to do when it goes to the wrong place.",
    sections: [
      {
        heading: "Personal data and the law",
        paragraphs: [
          "Personal data is anything that identifies a person: names with phone numbers, ID and passport numbers, KRA PINs, medical records, salaries, account numbers, photos. Laws such as Kenya's Data Protection Act 2019, Nigeria's Data Protection Act 2023 and South Africa's POPIA require organizations to protect it and to report serious breaches quickly (in Kenya, to the Data Commissioner within 72 hours).",
          "Most data leaks are not hacks: they are emails to the wrong person, files shared publicly, or lists left on personal phones.",
        ],
      },
      {
        heading: "Safe habits",
        paragraphs: ["Share only what is needed, only with who needs it:"],
        tips: [
          "Double-check recipients before sending, especially with auto-complete.",
          "Share files with named people, not “anyone with the link”.",
          "Do not move work data to personal email, WhatsApp or USB drives.",
          "Shred or securely delete what you no longer need.",
          "If data goes to the wrong place, report it to IT or the data protection officer immediately: the clock for notifying the regulator has started.",
        ],
      },
    ],
    quiz: [
      { id: "q1", question: "You emailed a spreadsheet of customer ID numbers to the wrong external address. What next?", options: ["Hope they ignore it", "Report it immediately to IT / the data protection officer", "Send a second email asking them to delete it and say nothing", "Delete it from your sent items"], correct: 1, explain: "This is a personal-data breach; the organization may have to notify the regulator within strict deadlines." },
      { id: "q2", question: "Which is the safest way to share a payroll file with the finance manager?", options: ["A public “anyone with the link” share", "Share with the finance manager's named account only", "Send it to their personal Gmail", "Post it in a WhatsApp group"], correct: 1, explain: "Named sharing keeps access limited and auditable." },
      { id: "q3", question: "Which of these is personal data?", options: ["A list of names with phone numbers", "The office opening hours", "A product price list", "The company logo"], correct: 0, explain: "Anything that identifies a person is personal data." },
      { id: "q4", question: "Most data leaks are caused by:", options: ["Hollywood-style hackers", "Everyday mistakes such as wrong recipients and public shares", "Power cuts", "Old computers"], correct: 1, explain: "Simple habits prevent most leaks." },
    ],
  },
];

export function lessonByKey(key: string): Lesson | undefined {
  return LESSONS.find((l) => l.key === key);
}

/** A lesson as learners see it before answering (no correct answers, no explanations). */
export type LessonForLearner = Omit<Lesson, "quiz"> & { quiz: Array<Pick<QuizQuestion, "id" | "question" | "options">> };
export function lessonForLearner(l: Lesson): LessonForLearner {
  return { ...l, quiz: l.quiz.map(({ id, question, options }) => ({ id, question, options })) };
}

export const QuizSubmission = z.object({ answers: z.record(z.string().max(20), z.number().int().min(0).max(10)) }).strict();
export type QuizSubmission = z.infer<typeof QuizSubmission>;

export interface QuizResult {
  score: number;
  passed: boolean;
  questions: Array<{ id: string; correct: boolean; correctOption: number; explain: string }>;
}

export function gradeQuiz(lesson: Lesson, answers: Record<string, number>): QuizResult {
  const questions = lesson.quiz.map((q) => ({ id: q.id, correct: answers[q.id] === q.correct, correctOption: q.correct, explain: q.explain }));
  const score = Math.round((questions.filter((q) => q.correct).length / lesson.quiz.length) * 100);
  return { score, passed: score >= PASS_MARK, questions };
}

export const AwarenessLearnerInput = z.object({ organizationId: z.guid(), name: z.string().trim().min(1).max(200), email: z.string().trim().toLowerCase().email().max(320) }).strict();
export type AwarenessLearnerInput = z.infer<typeof AwarenessLearnerInput>;

export const AwarenessAssignmentInput = z
  .object({
    organizationId: z.guid(),
    title: z.string().trim().min(3).max(200),
    lessons: z.array(z.string()).min(1).max(20).refine((ks) => ks.every((k) => lessonByKey(k)), "Unknown lesson"),
    dueAt: z.string().datetime().optional(),
    /** Email reminders when the training is due within 3 days or overdue (needs SMTP). */
    reminders: z.boolean().optional(),
    /** Learner ids; omitted = every active learner of the organization. */
    learnerIds: z.array(z.guid()).max(5000).optional(),
  })
  .strict();
export type AwarenessAssignmentInput = z.infer<typeof AwarenessAssignmentInput>;

export interface AwarenessLearner {
  id: string;
  name: string;
  email: string;
  source: "manual" | "directory";
  createdAt: string;
  assigned: number;
  completed: number;
  averageScore: number | null;
  risk: HumanRisk;
}

export interface AwarenessEnrolment {
  id: string;
  learnerId: string;
  learnerName: string;
  learnerEmail: string;
  invitedAt: string | null;
  remindedAt: string | null;
  completedAt: string | null;
  lessonsPassed: number;
  averageScore: number | null;
}

export interface AwarenessAssignment {
  id: string;
  title: string;
  lessons: string[];
  dueAt: string | null;
  reminders: boolean;
  createdAt: string;
  enrolments: AwarenessEnrolment[];
}

// ─── Phishing simulations ──────────────────────────────────────────────────

/**
 * Simulated phishing emails. Senders are generic roles, never real brands or domains; mail is sent
 * from the platform's own address with an X-SCIAT-Simulation header so gateways can allowlist it.
 * The link only ever opens SCIAT's "this was a simulation" page; nothing asks for a password.
 * Placeholders: {{name}}, {{org}}, {{link}}.
 */
export interface PhishTemplate {
  key: string;
  name: string;
  difficulty: "easy" | "medium" | "hard";
  fromName: string;
  subject: string;
  body: string;
  /** Lesson assigned to people who click (when the campaign asks for it). */
  lesson: string;
  /** What the learner should have noticed, shown on the reveal page. */
  redFlags: string[];
}

export const PHISH_TEMPLATES: PhishTemplate[] = [
  {
    key: "mailbox_full",
    name: "Mailbox almost full",
    difficulty: "easy",
    fromName: "IT Service Desk",
    subject: "Action required: your mailbox is 98% full",
    body: "Dear {{name}},\n\nYour mailbox has reached 98% of its storage limit. New messages will be rejected within 24 hours.\n\nTo keep receiving email, verify your account and request more storage here:\n{{link}}\n\nIT Service Desk",
    lesson: "phishing",
    redFlags: ["Pressure: messages “rejected within 24 hours”.", "Generic sender “IT Service Desk” from an address that is not your IT team's.", "A link to “verify your account”: real storage warnings never ask you to sign in from a link."],
  },
  {
    key: "parcel",
    name: "Failed parcel delivery",
    difficulty: "easy",
    fromName: "Delivery Notifications",
    subject: "We could not deliver your parcel today",
    body: "Hello {{name}},\n\nOur courier attempted to deliver a parcel to your office today but nobody was available to sign.\n\nPlease choose a new delivery slot within 48 hours, otherwise the parcel will be returned to the sender:\n{{link}}\n\nThank you,\nDelivery Notifications",
    lesson: "phishing",
    redFlags: ["You were not expecting a parcel, and no courier name or tracking number is given.", "A deadline to make you act before thinking.", "The link goes to an unknown site rather than a courier you know."],
  },
  {
    key: "invoice_overdue",
    name: "Overdue invoice",
    difficulty: "medium",
    fromName: "Accounts Receivable",
    subject: "Overdue invoice INV-20419 – final reminder",
    body: "Dear {{name}},\n\nOur records show invoice INV-20419 for services delivered to {{org}} is now 30 days overdue. Late-payment charges apply from tomorrow.\n\nPlease review the invoice and remittance details here:\n{{link}}\n\nRegards,\nAccounts Receivable",
    lesson: "payment_fraud",
    redFlags: ["An invoice you cannot match to a real supplier or order.", "Threat of late charges to rush you.", "Payment details reached through a link instead of your finance process."],
  },
  {
    key: "bank_details",
    name: "Supplier bank details changed",
    difficulty: "hard",
    fromName: "Supplier Accounts",
    subject: "Updated remittance details for future payments",
    body: "Good morning {{name}},\n\nPlease note that, following our annual audit, our company bank account has changed with immediate effect. All payments for open invoices should go to the new account.\n\nThe signed letter with the new details is here:\n{{link}}\n\nKind regards,\nSupplier Accounts",
    lesson: "payment_fraud",
    redFlags: ["A change of bank details announced by email.", "“With immediate effect”: urgency on a payment change.", "Bank changes must always be confirmed by phone on a number you already have."],
  },
  {
    key: "password_expiry",
    name: "Password expires today",
    difficulty: "medium",
    fromName: "IT Security",
    subject: "Your password expires today",
    body: "Hi {{name}},\n\nYour network password expires at 17:00 today. To avoid being locked out, keep your current password using the secure link below:\n{{link}}\n\nIT Security Team",
    lesson: "passwords_mfa",
    redFlags: ["A deadline the same day.", "“Keep your current password” through a link: real password changes happen in Windows or your company portal.", "IT never asks you to sign in from an email link."],
  },
  {
    key: "leave_policy",
    name: "Updated leave policy",
    difficulty: "hard",
    fromName: "Human Resources",
    subject: "Updated leave policy – acknowledgement required by Friday",
    body: "Dear {{name}},\n\nThe leave and public-holiday policy for {{org}} has been updated for next year. All staff must read and acknowledge the new policy by Friday.\n\nOpen the policy document:\n{{link}}\n\nHuman Resources",
    lesson: "phishing",
    redFlags: ["An internal-sounding sender from an external address.", "A document link instead of the usual HR system or intranet.", "Plausible and boring on purpose: the hardest phishing looks routine."],
  },
  {
    key: "mobile_money_bonus",
    name: "Mobile-money cash bonus",
    difficulty: "easy",
    fromName: "Mobile Money Rewards",
    subject: "Congratulations! A cash bonus is waiting for you",
    body: "Dear customer,\n\nYou have been selected to receive a loyalty cash bonus to your mobile-money wallet. Confirm your number and PIN within 12 hours to receive it:\n{{link}}\n\nMobile Money Rewards",
    lesson: "sim_swap",
    redFlags: ["Free money you did not expect.", "A request for your PIN: no provider ever asks for it.", "“Dear customer” and a short deadline."],
  },
];

export function phishTemplate(key: string): PhishTemplate | undefined {
  return PHISH_TEMPLATES.find((t) => t.key === key);
}

export function renderPhish(t: PhishTemplate, vars: { name: string; org: string; link: string }): { subject: string; text: string } {
  const fill = (s: string) => s.replaceAll("{{name}}", vars.name).replaceAll("{{org}}", vars.org).replaceAll("{{link}}", vars.link);
  return { subject: fill(t.subject), text: fill(t.body) };
}

export const PhishCampaignInput = z
  .object({
    organizationId: z.guid(),
    name: z.string().trim().min(3).max(200),
    template: z.string().refine((k) => !!phishTemplate(k), "Unknown template"),
    learnerIds: z.array(z.guid()).max(5000).optional(),
    /** Assign the template's lesson to everyone who clicks. */
    autoAssign: z.boolean().default(true),
    /** What authorizes this simulation (contract clause, written approval). */
    reference: z.string().trim().min(3).max(500),
    /** The person launching confirms the organization authorized phishing tests of these people. */
    attest: z.literal(true),
  })
  .strict();
export type PhishCampaignInput = z.infer<typeof PhishCampaignInput>;

export interface PhishTarget {
  id: string;
  learnerName: string;
  learnerEmail: string;
  sentAt: string | null;
  sendError: string | null;
  clickedAt: string | null;
}

export interface PhishCampaign {
  id: string;
  name: string;
  template: string;
  autoAssign: boolean;
  reference: string;
  launchedAt: string;
  launchedBy: string | null;
  targets: PhishTarget[];
}

// ─── Human risk ────────────────────────────────────────────────────────────

/** What a person did in the last 12 months (training and phishing simulations). */
export interface HumanRiskFacts {
  phishClicks: number;
  phishSpotted: number;
  completedTraining: number;
  overdueTraining: number;
  averageScore: number | null;
}

export type HumanRiskLevel = "low" | "medium" | "high";

export interface HumanRisk {
  score: number;
  level: HumanRiskLevel;
  /** Each contribution in plain language, largest first. */
  reasons: Array<{ points: number; text: string }>;
}

/**
 * Transparent 0–100 score (higher = more likely to be fooled). Starts at 20 and moves with
 * behaviour: clicking simulations weighs most; spotting them, finishing training and strong quiz
 * results bring it down. Every point is explained.
 */
export function humanRisk(f: HumanRiskFacts): HumanRisk {
  const reasons: Array<{ points: number; text: string }> = [{ points: 20, text: "Baseline for everyone" }];
  if (f.phishClicks) reasons.push({ points: Math.min(50, 25 * f.phishClicks), text: `Clicked ${f.phishClicks} phishing simulation${f.phishClicks === 1 ? "" : "s"}` });
  if (f.phishSpotted) reasons.push({ points: -Math.min(15, 5 * f.phishSpotted), text: `Did not fall for ${f.phishSpotted} simulation${f.phishSpotted === 1 ? "" : "s"}` });
  if (f.completedTraining === 0) reasons.push({ points: 15, text: "No training completed in the last 12 months" });
  else reasons.push({ points: -Math.min(10, 5 * f.completedTraining), text: `Completed ${f.completedTraining} training assignment${f.completedTraining === 1 ? "" : "s"}` });
  if (f.overdueTraining) reasons.push({ points: Math.min(20, 10 * f.overdueTraining), text: `${f.overdueTraining} training assignment${f.overdueTraining === 1 ? "" : "s"} overdue` });
  if (f.averageScore !== null && f.averageScore >= 90) reasons.push({ points: -10, text: `Strong quiz results (${f.averageScore}%)` });
  else if (f.averageScore !== null && f.averageScore < PASS_MARK) reasons.push({ points: 10, text: `Weak quiz results (${f.averageScore}%)` });
  const score = Math.max(0, Math.min(100, reasons.reduce((n, r) => n + r.points, 0)));
  return { score, level: score >= 60 ? "high" : score >= 35 ? "medium" : "low", reasons: reasons.sort((a, b) => Math.abs(b.points) - Math.abs(a.points)) };
}
