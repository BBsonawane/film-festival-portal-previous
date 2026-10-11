package portal;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.servlet.annotation.*;
import javax.servlet.http.*;

/** Increments 1-2 of the SRS: auth + roles, festival creation, jury requests, submission, payment, eligibility, notifications, audit trail. */
@WebServlet("/")
@MultipartConfig(maxFileSize = 2_000_000, maxRequestSize = 3_000_000)
public class Portal extends HttpServlet {
    static final Pattern HOST = Pattern.compile("^https://((www\\.)?youtube\\.com|youtu\\.be|drive\\.google\\.com)/\\S+$");
    static final Path UP = Paths.get(System.getenv().getOrDefault("UPLOAD_DIR", "/tmp/posters"));
    static final SecureRandom RND = new SecureRandom();

    // ---------- helpers ----------
    static String e(Object o) { return o == null ? "" : o.toString().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"); }
    static void bind(PreparedStatement p, Object[] a) throws SQLException { for (int i = 0; i < a.length; i++) p.setObject(i + 1, a[i]); }
    static List<Map<String, Object>> db(String sql, Object... a) throws Exception {
        try (Connection c = Db.c(); PreparedStatement p = c.prepareStatement(sql)) {
            bind(p, a);
            ResultSet rs = p.executeQuery(); var m = rs.getMetaData(); var out = new ArrayList<Map<String, Object>>();
            while (rs.next()) { var row = new HashMap<String, Object>(); for (int i = 1; i <= m.getColumnCount(); i++) row.put(m.getColumnLabel(i), rs.getObject(i)); out.add(row); }
            return out;
        }
    }
    static long up(String sql, Object... a) throws Exception {
        try (Connection c = Db.c(); PreparedStatement p = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            bind(p, a); p.executeUpdate();
            try (ResultSet k = p.getGeneratedKeys()) { return k.next() ? k.getLong(1) : 0; }
        }
    }
    static void note(int uid, String msg) throws Exception { up("INSERT INTO notifications(user_id,message) VALUES(?,?)", uid, msg); }
    static void audit(int fid, int uid, String action, String detail) throws Exception { up("INSERT INTO audit_log(festival_id,admin_id,action,detail) VALUES(?,?,?,?)", fid, uid, action, detail); }
    static String need(HttpServletRequest q, String k) {
        String v = q.getParameter(k);
        if (v == null || v.isBlank()) throw new IllegalArgumentException("Please fill in: " + k.replace('_', ' '));
        return v.trim();
    }
    static int num(Object o) { return ((Number) o).intValue(); }
    static String hash(String pw, byte[] salt) throws Exception {
        var f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return Base64.getEncoder().encodeToString(f.generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 120000, 256)).getEncoded());
    }
    static String field(String label, String name, String type, String extra) {
        return "<div class=mb-3><label class=form-label>" + label + "</label><input class=form-control name=" + name + " type=" + type + " required " + extra + "></div>";
    }
    static void guard(HttpSession s, String role) { if (!role.equals(s.getAttribute("role"))) throw new IllegalArgumentException("This action is not available for your account type."); }

    void page(HttpServletRequest q, HttpServletResponse r, String body) throws IOException {
        r.setContentType("text/html;charset=UTF-8");
        Object n = q.getSession().getAttribute("name");
        String nav = n == null ? "<a class='btn btn-sm btn-outline-dark' href='/login'>Log in</a>"
            : "<span class='text-dark me-3'>" + e(n) + "</span><a class='btn btn-sm btn-outline-dark' href='/logout'>Log out</a>";
        r.getWriter().print("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Film Festival Portal</title>"
            + "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel=stylesheet>"
            + "<style>:root{--bs-body-bg:#FFFBE9;--bs-body-color:#2e231b;--bs-link-color:#7a563f;--bs-link-hover-color:#2e231b;--bs-border-color:#CEAB93}body{background:#FFFBE9;color:#2e231b}nav{background:#AD8B73}.btn-primary{--bs-btn-color:#2e231b;--bs-btn-bg:#AD8B73;--bs-btn-border-color:#AD8B73;--bs-btn-hover-color:#2e231b;--bs-btn-hover-bg:#CEAB93;--bs-btn-hover-border-color:#CEAB93;--bs-btn-active-color:#2e231b;--bs-btn-active-bg:#E3CAA5;--bs-btn-active-border-color:#E3CAA5}.btn-outline-dark{--bs-btn-color:#2e231b;--bs-btn-border-color:#2e231b;--bs-btn-hover-bg:#2e231b;--bs-btn-hover-color:#FFFBE9}.btn-outline-secondary{--bs-btn-color:#7a563f;--bs-btn-border-color:#AD8B73;--bs-btn-hover-bg:#E3CAA5;--bs-btn-hover-color:#2e231b;--bs-btn-hover-border-color:#AD8B73}table{--bs-table-bg:transparent;--bs-table-border-color:#CEAB93}th{background:#E3CAA5}.form-control,.form-select{background:#FFFBE9;border-color:#CEAB93}.form-control:focus,.form-select:focus{background:#FFFBE9;border-color:#AD8B73;box-shadow:0 0 0 .2rem #E3CAA5}.text-bg-secondary{background:#CEAB93!important;color:#2e231b!important}</style>"
            + "<nav class='navbar px-3'><a class='navbar-brand text-dark' href='/'>Film Festival Portal</a><div>" + nav + "</div></nav>"
            + "<main class='container py-4'>" + body + "</main></html>");
    }

    // ---------- routing ----------
    @Override protected void service(HttpServletRequest q, HttpServletResponse r) throws IOException {
        try { route(q, r); }
        catch (IllegalArgumentException | IllegalStateException ex) { r.setStatus(400); page(q, r, "<div class='alert alert-danger'>" + e(ex.getMessage()) + "</div><a href='/dashboard'>Back to dashboard</a>"); }
        catch (Exception ex) { log("request failed", ex); r.setStatus(500); page(q, r, "<div class='alert alert-danger'>Something went wrong. Please try again.</div>"); }
    }

    void route(HttpServletRequest q, HttpServletResponse r) throws Exception {
        String p = q.getServletPath(); boolean post = q.getMethod().equals("POST");
        HttpSession s = q.getSession();
        Integer uid = (Integer) s.getAttribute("uid");
        switch (p) {
            case "/" -> { if (uid != null) r.sendRedirect("/dashboard"); else page(q, r, "<h1>Submit, judge and screen short films.</h1><p class=lead>One place for filmmakers, jury members and festival admins.</p><a class='btn btn-primary me-2' href='/register'>Create account</a><a class='btn btn-outline-secondary' href='/login'>Log in</a>"); }
            case "/register" -> { if (post) register(q, r); else page(q, r, "<h2>Create your account</h2><form method=post class='col-md-5'>" + field("Name", "name", "text", "") + field("Email", "email", "email", "") + field("Password (8+ characters)", "password", "password", "minlength=8") + "<div class=mb-3><label class=form-label>I am a</label><select class=form-select name=role><option value=FILMMAKER>Filmmaker<option value=NONFILMMAKER>Non-filmmaker (create a festival or join as jury)</select></div><button class='btn btn-primary'>Register</button></form>"); }
            case "/login" -> { if (post) login(q, r); else page(q, r, "<h2>Log in</h2><form method=post class='col-md-5'>" + field("Email", "email", "email", "") + field("Password", "password", "password", "") + "<button class='btn btn-primary'>Log in</button></form>"); }
            case "/logout" -> { s.invalidate(); r.sendRedirect("/"); }
            default -> {
                if (uid == null) { r.sendRedirect("/login"); return; }
                String role = (String) s.getAttribute("role");
                switch (p) {
                    case "/dashboard" -> dashboard(q, r, uid, role);
                    case "/festival/create" -> { guard(s, "NONFILMMAKER"); createFestival(q, r, uid); }
                    case "/festival" -> { guard(s, "NONFILMMAKER"); festival(q, r, uid); }
                    case "/jury/request" -> { guard(s, "NONFILMMAKER"); up("INSERT IGNORE INTO jury_requests(festival_id,user_id) SELECT id,? FROM festivals WHERE id=? AND admin_id<>?", uid, need(q, "festival_id"), uid); r.sendRedirect("/dashboard"); }
                    case "/jury/approve" -> { guard(s, "NONFILMMAKER"); approve(q, r, uid); }
                    case "/submit" -> { guard(s, "FILMMAKER"); if (post) submit(q, r, uid); else submitForm(q, r); }
                    case "/pay" -> { guard(s, "FILMMAKER"); if (post) { settle(Integer.parseInt(need(q, "id")), uid, "SUCCESS".equals(q.getParameter("result"))); r.sendRedirect("/dashboard"); } else payPage(q, r, uid); }
                    case "/assign" -> { guard(s, "NONFILMMAKER"); assign(q, r, uid); }
                    case "/review" -> { guard(s, "NONFILMMAKER"); if (post) saveScores(q, r, uid); else review(q, r, uid); }
                    case "/poster" -> poster(q, r);
                    default -> r.sendError(404);
                }
            }
        }
    }

    // ---------- Increment 1: auth, roles, festivals ----------
    void register(HttpServletRequest q, HttpServletResponse r) throws Exception {
        String role = need(q, "role"), pw = need(q, "password");
        if (!role.equals("FILMMAKER") && !role.equals("NONFILMMAKER")) throw new IllegalArgumentException("Choose a valid account type.");
        if (pw.length() < 8) throw new IllegalArgumentException("Password must be at least 8 characters.");
        byte[] salt = new byte[16]; RND.nextBytes(salt);
        try { up("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)", need(q, "name"), need(q, "email").toLowerCase(), Base64.getEncoder().encodeToString(salt) + ":" + hash(pw, salt), role); }
        catch (SQLIntegrityConstraintViolationException ex) { throw new IllegalArgumentException("That email is already registered."); }
        r.sendRedirect("/login");
    }

    void login(HttpServletRequest q, HttpServletResponse r) throws Exception {
        var u = db("SELECT * FROM users WHERE email=?", need(q, "email").toLowerCase());
        if (u.isEmpty()) throw new IllegalArgumentException("Wrong email or password.");
        String[] parts = ((String) u.get(0).get("password_hash")).split(":");
        byte[] given = Base64.getDecoder().decode(hash(need(q, "password"), Base64.getDecoder().decode(parts[0])));
        if (!MessageDigest.isEqual(given, Base64.getDecoder().decode(parts[1]))) throw new IllegalArgumentException("Wrong email or password.");
        q.changeSessionId();
        HttpSession s = q.getSession();
        s.setAttribute("uid", num(u.get(0).get("id"))); s.setAttribute("role", u.get(0).get("role")); s.setAttribute("name", u.get(0).get("name"));
        r.sendRedirect("/dashboard");
    }

    void createFestival(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        int sum = 0; var crit = new ArrayList<Object[]>();
        for (String line : need(q, "rubric").split("\\R")) {
            if (line.isBlank()) continue;
            String[] kv = line.split(":");
            if (kv.length != 2) throw new IllegalArgumentException("Rubric lines must look like Story:40");
            int w = Integer.parseInt(kv[1].trim()); crit.add(new Object[]{kv[0].trim(), w}); sum += w;
        }
        if (sum != 100) throw new IllegalArgumentException("Rubric weights must add up to 100.");
        long fid = up("INSERT INTO festivals(admin_id,name,deadline,max_runtime_min) VALUES(?,?,?,?)", uid, need(q, "name"), Timestamp.valueOf(LocalDateTime.parse(need(q, "deadline"))), Integer.parseInt(need(q, "max_runtime")));
        for (Object[] c : crit) up("INSERT INTO rubric_criteria(festival_id,name,weight) VALUES(?,?,?)", fid, c[0], c[1]);
        audit((int) fid, uid, "FESTIVAL_CREATED", need(q, "name"));
        r.sendRedirect("/festival?id=" + fid);
    }

    void festival(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        int id = Integer.parseInt(need(q, "id"));
        var f = db("SELECT * FROM festivals WHERE id=? AND admin_id=?", id, uid);
        if (f.isEmpty()) throw new IllegalArgumentException("Only the festival's admin can open this page.");
        var b = new StringBuilder("<h2>" + e(f.get(0).get("name")) + "</h2><p>Deadline " + e(f.get(0).get("deadline")) + " · max " + f.get(0).get("max_runtime_min") + " min</p>");
        b.append("<h4 class=mt-4>Jury requests</h4><table class=table><tr><th>Name<th>Status<th></tr>");
        for (var j : db("SELECT j.id,j.status,u.name FROM jury_requests j JOIN users u ON u.id=j.user_id WHERE j.festival_id=?", id)) {
            b.append("<tr><td>").append(e(j.get("name"))).append("<td>").append(j.get("status")).append("<td>");
            if ("PENDING".equals(j.get("status"))) b.append("<form method=post action='/jury/approve'><input type=hidden name=id value=").append(j.get("id")).append("><button class='btn btn-sm btn-primary'>Approve</button></form>");
            b.append("</tr>");
        }
        var jury = db("SELECT u.id,u.name FROM jury_requests j JOIN users u ON u.id=j.user_id WHERE j.festival_id=? AND j.status='APPROVED'", id);
        b.append("</table><h4 class=mt-4>Submissions</h4><table class=table><tr><th>Film<th>Tracking ID<th>Status<th>Assigned jury</tr>");
        for (var s : db("SELECT id,title,tracking_id,status,reason,CAST((SELECT GROUP_CONCAT(u.name SEPARATOR ', ') FROM assignments a JOIN users u ON u.id=a.jury_id WHERE a.submission_id=submissions.id) AS CHAR) jurors FROM submissions WHERE festival_id=? ORDER BY id DESC", id)) {
            b.append("<tr><td>").append(e(s.get("title"))).append("<td>").append(e(s.get("tracking_id"))).append("<td>").append(s.get("status")).append(" ").append(e(s.get("reason"))).append("<td>").append(e(s.get("jurors"))).append(" ");
            if ("ELIGIBLE".equals(s.get("status")) && !jury.isEmpty()) {
                b.append("<form method=post action='/assign'><input type=hidden name=submission_id value=").append(s.get("id")).append(">");
                for (var j : jury) b.append("<label class=me-2><input type=checkbox name=jury_id value=").append(j.get("id")).append("> ").append(e(j.get("name"))).append("</label>");
                b.append("<button class='btn btn-sm btn-primary'>Assign</button></form>");
            }
            b.append("</tr>");
        }
        b.append("</table><h4 class=mt-4>Audit trail</h4><ul class=list-unstyled>");
        for (var a : db("SELECT action,detail,created_at FROM audit_log WHERE festival_id=? ORDER BY id DESC LIMIT 30", id))
            b.append("<li>").append(e(a.get("created_at"))).append(" — ").append(e(a.get("action"))).append(" ").append(e(a.get("detail"))).append("</li>");
        page(q, r, b.append("</ul>").toString());
    }

    void approve(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        int id = Integer.parseInt(need(q, "id"));
        var j = db("SELECT j.user_id,j.festival_id FROM jury_requests j JOIN festivals f ON f.id=j.festival_id WHERE j.id=? AND f.admin_id=?", id, uid);
        if (j.isEmpty()) throw new IllegalArgumentException("Only the festival's admin can approve jury requests.");
        up("UPDATE jury_requests SET status='APPROVED' WHERE id=?", id);
        note(num(j.get(0).get("user_id")), "Your request to join a festival as jury was approved.");
        audit(num(j.get(0).get("festival_id")), uid, "JURY_APPROVED", "request " + id);
        r.sendRedirect("/festival?id=" + j.get(0).get("festival_id"));
    }

    void dashboard(HttpServletRequest q, HttpServletResponse r, int uid, String role) throws Exception {
        var b = new StringBuilder("<h2>Dashboard</h2>");
        if (role.equals("FILMMAKER")) {
            b.append("<h4 class=mt-4>Festivals open for submissions</h4>");
            for (var f : db("SELECT id,name,deadline FROM festivals WHERE deadline>NOW() ORDER BY deadline"))
                b.append("<p>").append(e(f.get("name"))).append(" — closes ").append(e(f.get("deadline"))).append(" <a class='btn btn-sm btn-primary' href='/submit?festival=").append(f.get("id")).append("'>Submit a film</a></p>");
            b.append("<h4 class=mt-4>My submissions</h4><table class=table><tr><th>Film<th>Festival<th>Tracking ID<th>Status<th></tr>");
            for (var s : db("SELECT s.id,s.title,s.status,s.reason,s.tracking_id,f.name fn FROM submissions s JOIN festivals f ON f.id=s.festival_id WHERE s.filmmaker_id=? ORDER BY s.id DESC", uid)) {
                b.append("<tr><td>").append(e(s.get("title"))).append("<td>").append(e(s.get("fn"))).append("<td>").append(e(s.get("tracking_id"))).append("<td>").append(s.get("status")).append(" ").append(e(s.get("reason"))).append("<td>");
                if ("PENDING_PAYMENT".equals(s.get("status"))) b.append("<a href='/pay?id=").append(s.get("id")).append("'>Pay now</a>");
                b.append("</tr>");
            }
            b.append("</table>");
        } else {
            b.append("<h4 class=mt-4>Create a festival</h4><form method=post action='/festival/create' class='col-md-6'>")
             .append(field("Festival name", "name", "text", "")).append(field("Submission deadline", "deadline", "datetime-local", "")).append(field("Maximum film length (minutes)", "max_runtime", "number", "min=1 value=40"))
             .append("<div class=mb-3><label class=form-label>Scoring rubric: one criterion:weight per line, weights add up to 100</label><textarea class=form-control name=rubric rows=3>Story:40\nDirection:30\nTechnical quality:30</textarea></div><button class='btn btn-primary'>Create festival</button></form>");
            b.append("<h4 class=mt-4>Festivals I run</h4>");
            for (var f : db("SELECT id,name FROM festivals WHERE admin_id=?", uid)) b.append("<p><a href='/festival?id=").append(f.get("id")).append("'>").append(e(f.get("name"))).append("</a></p>");
            b.append("<h4 class=mt-4>Join a festival as jury</h4>");
            for (var f : db("SELECT f.id,f.name,j.status FROM festivals f LEFT JOIN jury_requests j ON j.festival_id=f.id AND j.user_id=? WHERE f.admin_id<>?", uid, uid)) {
                b.append("<form method=post action='/jury/request' class='mb-2'>").append(e(f.get("name"))).append(" ");
                if (f.get("status") == null) b.append("<input type=hidden name=festival_id value=").append(f.get("id")).append("><button class='btn btn-sm btn-primary'>Request to join</button>");
                else b.append("<span class='badge text-bg-secondary'>").append(f.get("status")).append("</span>");
                b.append("</form>");
            }
        }
        if (role.equals("NONFILMMAKER")) {
            b.append("<h4 class=mt-4>Films assigned to me for review</h4>");
            for (var a : db("SELECT s.id,s.tracking_id,s.title,f.name fn,(SELECT COUNT(*) FROM scores sc WHERE sc.submission_id=s.id AND sc.jury_id=a.jury_id) scored FROM assignments a JOIN submissions s ON s.id=a.submission_id JOIN festivals f ON f.id=s.festival_id WHERE a.jury_id=?", uid))
                b.append("<p><a href='/review?id=").append(a.get("id")).append("'>").append(e(a.get("tracking_id"))).append(" ").append(e(a.get("title"))).append("</a> (").append(e(a.get("fn"))).append(")").append(num(a.get("scored")) > 0 ? " · scored" : " · not scored yet").append("</p>");
        }
        b.append("<h4 class=mt-4>Notifications</h4><ul class=list-unstyled>");
        for (var n : db("SELECT message,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 10", uid)) b.append("<li>").append(e(n.get("created_at"))).append(" — ").append(e(n.get("message"))).append("</li>");
        page(q, r, b.append("</ul>").toString());
    }

    // ---------- Increment 2: submission, payment, eligibility ----------
    void submitForm(HttpServletRequest q, HttpServletResponse r) throws Exception {
        var f = db("SELECT name FROM festivals WHERE id=?", need(q, "festival"));
        if (f.isEmpty()) throw new IllegalArgumentException("Festival not found.");
        page(q, r, "<h2>Submit a film to " + e(f.get(0).get("name")) + "</h2><form method=post enctype='multipart/form-data' class='col-md-6'><input type=hidden name=festival value='" + e(q.getParameter("festival")) + "'>"
            + field("Title", "title", "text", "") + field("Genre", "genre", "text", "") + field("Duration (minutes)", "duration", "number", "min=1")
            + "<div class=mb-3><label class=form-label>Synopsis</label><textarea class=form-control name=synopsis rows=3 required></textarea></div>"
            + field("Trailer link (YouTube or Google Drive)", "trailer", "url", "") + field("Full film link (YouTube or Google Drive)", "film", "url", "")
            + "<div class=mb-3><label class=form-label>Poster (JPEG or PNG, up to 2 MB)</label><input class=form-control type=file name=poster accept='image/jpeg,image/png' required></div><button class='btn btn-primary'>Continue to payment</button></form>");
    }

    void submit(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        String trailer = need(q, "trailer"), film = need(q, "film");
        if (!HOST.matcher(trailer).matches() || !HOST.matcher(film).matches()) throw new IllegalArgumentException("Links must be https URLs on YouTube or Google Drive.");
        Part pt = q.getPart("poster"); String ct = pt == null ? "" : pt.getContentType();
        if (pt == null || pt.getSize() == 0 || !(ct.equals("image/jpeg") || ct.equals("image/png"))) throw new IllegalArgumentException("Poster must be a JPEG or PNG up to 2 MB.");
        int dur = Integer.parseInt(need(q, "duration"));
        Files.createDirectories(UP);
        String fn = Long.toHexString(RND.nextLong()) + (ct.equals("image/png") ? ".png" : ".jpg");
        try (InputStream in = pt.getInputStream()) { Files.copy(in, UP.resolve(fn)); }
        long id = up("INSERT INTO submissions(festival_id,filmmaker_id,title,genre,duration_min,synopsis,trailer_url,film_url,poster_file,status) VALUES(?,?,?,?,?,?,?,?,?,'PENDING_PAYMENT')",
            need(q, "festival"), uid, need(q, "title"), need(q, "genre"), dur, need(q, "synopsis"), trailer, film, fn);
        r.sendRedirect("/pay?id=" + id);
    }

    void payPage(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        var s = db("SELECT title FROM submissions WHERE id=? AND filmmaker_id=? AND status='PENDING_PAYMENT'", need(q, "id"), uid);
        if (s.isEmpty()) throw new IllegalArgumentException("Nothing to pay for.");
        page(q, r, "<h2>Registration payment</h2><p>Sandbox gateway for <b>" + e(s.get(0).get("title")) + "</b>. Pick an outcome to simulate.</p><form method=post><input type=hidden name=id value='" + e(q.getParameter("id")) + "'>"
            + "<button name=result value=SUCCESS class='btn btn-primary me-2'>Pay (test success)</button><button name=result value=FAIL class='btn btn-outline-danger'>Simulate failure</button></form>");
    }

    /** Stand-in for the gateway webhook: payment is only trusted here, on the server (REQ-2.7). */
    void settle(int id, int uid, boolean ok) throws Exception {
        var rows = db("SELECT s.title,IF(s.duration_min>f.max_runtime_min,1,0) too_long,IF(NOW()>f.deadline,1,0) late FROM submissions s JOIN festivals f ON f.id=s.festival_id WHERE s.id=? AND s.filmmaker_id=? AND s.status='PENDING_PAYMENT'", id, uid);
        if (rows.isEmpty()) throw new IllegalArgumentException("Nothing to pay for.");
        if (!ok) { up("UPDATE submissions SET status='INCOMPLETE',reason='Payment failed' WHERE id=?", id); note(uid, "Payment failed, so your submission is incomplete."); return; }
        String reason = num(rows.get(0).get("late")) == 1 ? "Received after the submission deadline" : num(rows.get(0).get("too_long")) == 1 ? "Runtime exceeds the festival limit" : null;
        String tid = String.format("FF-%06X", RND.nextInt(0xFFFFFF));
        up("UPDATE submissions SET tracking_id=?,status=?,reason=? WHERE id=?", tid, reason == null ? "ELIGIBLE" : "INELIGIBLE", reason, id);
        note(uid, "Submission received. Tracking ID " + tid + ".");
        note(uid, reason == null ? "Eligibility check passed." : "Eligibility check failed: " + reason + ".");
    }

    // ---------- Increment 3: assignment, blind review, weighted scoring ----------
    void assign(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        int sid = Integer.parseInt(need(q, "submission_id"));
        var s = db("SELECT s.festival_id,s.status,s.tracking_id FROM submissions s JOIN festivals f ON f.id=s.festival_id WHERE s.id=? AND f.admin_id=?", sid, uid);
        if (s.isEmpty()) throw new IllegalArgumentException("Only the festival's admin can assign films.");
        if (!"ELIGIBLE".equals(s.get(0).get("status"))) throw new IllegalArgumentException("Only films that passed the eligibility check can be assigned.");
        String[] ids = q.getParameterValues("jury_id");
        if (ids == null) throw new IllegalArgumentException("Pick at least one jury member.");
        int fid = num(s.get(0).get("festival_id"));
        for (String j : ids) {
            int jid = Integer.parseInt(j);
            if (db("SELECT 1 x FROM jury_requests WHERE festival_id=? AND user_id=? AND status='APPROVED'", fid, jid).isEmpty()) throw new IllegalArgumentException("That person is not approved jury for this festival.");
            if (up("INSERT IGNORE INTO assignments(submission_id,jury_id) VALUES(?,?)", sid, jid) > 0) {
                note(jid, "A new film (" + s.get(0).get("tracking_id") + ") was assigned to you for review.");
                audit(fid, uid, "JURY_ASSIGNED", s.get(0).get("tracking_id") + " to user " + jid);
            }
        }
        r.sendRedirect("/festival?id=" + fid);
    }

    /** Blind: this query never selects filmmaker_id or any other identity field (REQ-5.3). */
    List<Map<String, Object>> mine(int sid, int uid) throws Exception {
        return db("SELECT s.id,s.tracking_id,s.title,s.genre,s.duration_min,s.synopsis,s.trailer_url,s.film_url,s.poster_file,s.festival_id FROM assignments a JOIN submissions s ON s.id=a.submission_id WHERE a.submission_id=? AND a.jury_id=?", sid, uid);
    }

    void review(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        int sid = Integer.parseInt(need(q, "id"));
        var m = mine(sid, uid);
        if (m.isEmpty()) throw new IllegalArgumentException("This film is not assigned to you.");
        var f = m.get(0);
        var b = new StringBuilder("<h2>Film " + e(f.get("tracking_id")) + ": " + e(f.get("title")) + "</h2><p>" + e(f.get("genre")) + " · " + f.get("duration_min") + " min</p>");
        b.append("<img src='/poster?f=" + e(f.get("poster_file")) + "' class='img-fluid mb-3' style='max-height:240px' alt='Poster'><p>" + e(f.get("synopsis")) + "</p>");
        b.append("<p><a target=_blank rel=noopener href='" + e(f.get("trailer_url")) + "'>Watch trailer</a> · <a target=_blank rel=noopener href='" + e(f.get("film_url")) + "'>Watch full film</a></p>");
        var old = new HashMap<Integer, Object>();
        for (var o : db("SELECT criterion_id,score FROM scores WHERE submission_id=? AND jury_id=?", sid, uid)) old.put(num(o.get("criterion_id")), o.get("score"));
        b.append("<form method=post class='col-md-6'><input type=hidden name=id value=" + sid + ">");
        double total = 0; boolean all = true;
        for (var c : db("SELECT id,name,weight FROM rubric_criteria WHERE festival_id=? ORDER BY id", f.get("festival_id"))) {
            Object v = old.get(num(c.get("id")));
            if (v == null) all = false; else total += num(v) * num(c.get("weight")) / 10.0;
            b.append("<div class=mb-3><label class=form-label>" + e(c.get("name")) + " (weight " + c.get("weight") + "%), score 1 to 10</label><input class=form-control type=number min=1 max=10 required name=c" + c.get("id") + (v == null ? "" : " value=" + v) + "></div>");
        }
        b.append("<button class='btn btn-primary'>Save scores</button></form>");
        if (all) b.append("<p class=mt-3>Your weighted total: <b>" + String.format("%.1f", total) + " / 100</b></p>");
        page(q, r, b.toString());
    }

    void saveScores(HttpServletRequest q, HttpServletResponse r, int uid) throws Exception {
        int sid = Integer.parseInt(need(q, "id"));
        var m = mine(sid, uid);
        if (m.isEmpty()) throw new IllegalArgumentException("This film is not assigned to you.");
        var vals = new ArrayList<Object[]>();
        for (var c : db("SELECT id FROM rubric_criteria WHERE festival_id=?", m.get(0).get("festival_id"))) {
            int sc = Integer.parseInt(need(q, "c" + c.get("id")));
            if (sc < 1 || sc > 10) throw new IllegalArgumentException("Scores must be between 1 and 10.");
            vals.add(new Object[]{c.get("id"), sc});
        }
        for (Object[] v : vals) up("INSERT INTO scores(submission_id,jury_id,criterion_id,score) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE score=VALUES(score)", sid, uid, v[0], v[1]);
        r.sendRedirect("/review?id=" + sid);
    }

    void poster(HttpServletRequest q, HttpServletResponse r) throws Exception {
        Path f = UP.resolve(Paths.get(need(q, "f")).getFileName());
        if (!Files.exists(f)) { r.sendError(404); return; }
        r.setContentType(f.toString().endsWith(".png") ? "image/png" : "image/jpeg");
        Files.copy(f, r.getOutputStream());
    }
}
