-- Security Awareness: automatic reminders for unfinished training (due soon or overdue).
ALTER TABLE sat_assignments ADD COLUMN reminders boolean NOT NULL DEFAULT true;
ALTER TABLE sat_enrolments ADD COLUMN reminded_at timestamptz, ADD COLUMN reminder_count integer NOT NULL DEFAULT 0;
