# Film Festival Submission & Screening Portal

Java Servlets + MySQL + Bootstrap (per SRS v1.0). Built incrementally.

**Done (increments 1-5):** jury assignment, blind review, weighted scoring, Top 5 shortlist, discussion, voting, tie-break, admin confirm/override, post-publish anonymised comment visibility for filmmakers, audit trail search/filter; role-based register/login (salted PBKDF2), festival creation (creator becomes that festival's admin), jury requests + admin approval, film submission (poster upload, YouTube/Drive link validation), sandbox payment, auto eligibility check, tracking ID, notifications, admin audit trail.
**Not yet:** background timers and reminders for the 48h/24h windows, CSRF tokens, forgot-password.

## Run
    docker compose up --build        # http://localhost:8080

Without Docker: MySQL 8 + Tomcat 9, `mvn package`, deploy `target/ROOT.war`. Env vars: `DB_URL`, `DB_USER`, `DB_PASS`, `UPLOAD_DIR`. Tables are created on startup from `schema.sql`.

## Deploy
GitHub stores the code and builds it (Actions). GitHub Pages cannot run Tomcat or MySQL, so for a live URL point Render/Railway at the `Dockerfile` and a hosted MySQL, and set the env vars above.
