/* TST-005 오탐 시험용 안전 Java 샘플 — vulnerable.java의 각 취약점에 대한 올바른 대응 (SFR-011).
 *
 * 여기서 findings가 하나라도 나오면 룰이 과탐지하는 것이다(오탐). 정탐 못지않게
 * 중요한 기준이라 취약 샘플과 짝으로 유지한다. 이름 기준 룰(IV-15·SF-01)이 오탐이 되기
 * 쉬운 케이스 — 검증 후 쓰는 price, 표시용 role, 공개 경로의 permitAll — 를 일부러 넣어
 * 실측한다.
 */
package samples;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.naming.directory.*;
import javax.script.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;

public class SafeSample extends HttpServlet {
    private static final Logger LOG = Logger.getLogger("safe");
    private final String appName = "demo";                        // 요청과 무관한 설정 필드
    private int[] scores = new int[10];
    private String[] names;

    // DB 비밀번호는 시크릿 저장소 APP_DB_PASSWORD 항목에 있다 (값은 여기 적지 말 것)
    private static final String DB_PASSWORD = System.getenv("APP_DB_PASSWORD");
    private static final String API_TOKEN = "";

    public int[] getScores() { return scores.clone(); }                  // 복사본 반환
    public void setNames(String[] input) { this.names = input.clone(); } // 복사본 저장

    private static final Set<String> ALLOWED = Set.of("/home", "/profile");
    private static String escape(String s) { return s == null ? "" : s.replace("<", "&lt;"); }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");                       // 지역 변수 — 공유 안 됨

        String id = request.getParameter("id");
        if (id == null) { response.sendError(400); return; }
        try (Connection conn = conn();
             PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")) {
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();
        }

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval("1 + 1");

        Path base = Paths.get("/data").toRealPath();
        Path target = base.resolve(Paths.get(id).getFileName()).normalize();
        if (!target.startsWith(base)) { response.sendError(400); return; }
        try (InputStream in = Files.newInputStream(target)) { in.read(); }

        new ProcessBuilder("ping", "-c", "1", "127.0.0.1").start();
        Runtime.getRuntime().exec("uptime");
        Runtime.getRuntime().exec(new String[]{"ls", "-l"});

        String next = request.getParameter("next");
        if (next != null && ALLOWED.contains(next)) response.sendRedirect(next);
        else response.sendRedirect("/home");

        URL url = new URL("https://api.example.com/status");

        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + escape(user) + "</h1>");
        out.println("static text");

        response.setHeader("X-Frame-Options", "DENY");
        response.addCookie(new Cookie("lang", "ko"));

        String ua = request.getHeader("User-Agent");
        if (ua != null && ua.length() > 0) { }

        // IV-15 오탐 실측 — 권한은 서버 세션 값으로 결정한다.
        String sessionRole = (String) request.getSession().getAttribute("role");
        if ("admin".equals(sessionRole)) { }
        // IV-15 오탐 실측 — role이라는 이름이지만 화면 표시용으로만 쓴다.
        String role = request.getParameter("role");
        out.println("<p>requested role: " + escape(role) + "</p>");
        // IV-15 오탐 실측 — price를 검증 후 쓴다 (가격류는 룰 대상에서 제외).
        String price = request.getParameter("price");
        int p = price == null ? 0 : Integer.parseInt(price);
        if (p < 0 || p > 1_000_000) { response.sendError(400); return; }
        LOG.info("price " + p);

        Cookie c = new Cookie("session_token", id);
        c.setHttpOnly(true);                                               // maxAge 미지정 = 세션 쿠키
        Cookie theme = new Cookie("theme", "dark");
        theme.setMaxAge(60 * 60 * 24 * 30);                                 // 민감 이름 아님

        try {
            out.flush();
        } catch (Exception e) {
            LOG.severe("flush failed: " + e.getMessage());                  // 로그에만
            response.sendError(500, "internal error");
        }
        try { out.close(); } catch (Exception e) { LOG.warning("close: " + e); }
    }

    void crypto(String password, byte[] salt) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        sha.update(salt);
        byte[] hash = sha.digest(password.getBytes("UTF-8"));              // 솔트 후 해시

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072);

        byte[] token = new byte[32];
        new SecureRandom().nextBytes(token);
        int dice = new Random().nextInt(6) + 1;                              // 보안 용도 아님
    }

    void files(File file, MultipartFile upload) throws Exception {
        file.setWritable(true, true);                                        // owner only
        Files.setPosixFilePermissions(file.toPath(),
            java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----"));

        try (FileInputStream s = new FileInputStream(file)) { s.read(); }    // 검사 없이 열고 예외로 판단

        String safeName = UUID.randomUUID().toString() + ".bin";
        upload.transferTo(new File("/uploads/", safeName));
    }

    void xml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes()));
    }

    void ldap(DirContext ctx, String user) throws Exception {
        ctx.search("ou=people", "(uid={0})", new Object[]{user}, new SearchControls());
    }

    void deser(InputStream is) throws Exception {
        Object o = new com.fasterxml.jackson.databind.ObjectMapper().readValue(is, Map.class);
    }

    void threads(Thread t) throws Exception {
        t.interrupt();
        t.join();
    }

    void security(Object http) throws Exception {
        ((HttpSecurity) http).csrf();
        ((HttpSecurity) http).authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");
        // SF-01 오탐 실측 — 실제로 공개돼야 하는 경로의 permitAll.
        ((HttpSecurity) http).authorizeRequests().antMatchers("/public/**").permitAll();
        ((HttpSecurity) http).authorizeRequests().antMatchers("/login", "/css/**", "/js/**").permitAll();
        ((HttpSecurity) http).authorizeRequests().anyRequest().authenticated();
    }

    void tls(Object builder) throws Exception {
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getDefault();
    }

    Connection conn() throws Exception {
        return DriverManager.getConnection("jdbc:x", "app", System.getenv("APP_DB_PASSWORD"));
    }

    void reader(String path) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(path));
        try { br.readLine(); } finally { br.close(); }
    }

    FileInputStream open(File f) throws Exception {
        FileInputStream s = new FileInputStream(f);
        return s;
    }
}
