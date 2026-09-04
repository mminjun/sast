/* TST-005 정탐 시험용 취약 Java 샘플 — 의도적으로 취약하게 작성된 코드다 (SFR-011).
 *
 * 컴파일·실행하거나 참고용으로 복사하지 말 것. catalog/rules/java_*.yaml의 KISA 룰 35개가
 * 각각 정확히 걸리는지 확인하는 고정 자산이며, 안전한 대응 코드는 safe.java에 있다.
 * 기대 건수는 catalog/tests.py EXPECTED_JAVA_SAMPLE_FINDINGS.
 *
 * 우리 SAST로 우리 코드를 분석할 때(도그푸딩·CI 게이트) 당연히 탐지된다 —
 * 분석 대상에서 catalog/samples/를 제외하고 돌려야 한다.
 */
package samples;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.naming.directory.*;
import javax.script.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;

public class VulnerableSample extends HttpServlet {
    private String currentUser;                                  // EN-01 대상 필드
    private int[] scores = new int[10];
    private String[] names;

    // 운영 DB: password = Passw0rd!                            // SF-13
    private static final String DB_PASSWORD = "hunter2";        // SF-06 #1

    public int[] getScores() { return scores; }                  // EN-03
    public void setNames(String[] input) { this.names = input; } // EN-04

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        currentUser = request.getParameter("user");             // EN-01

        String id = request.getParameter("id");
        Statement st = conn().createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = " + id);   // IV-01 #1
        String sql = "DELETE FROM users WHERE name = '" + id + "'";
        st.executeUpdate(sql);                                                    // IV-01 #2

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval(request.getParameter("expr"));                                // IV-02

        File f = new File("/data/", request.getParameter("name"));                // IV-03 #1
        FileInputStream in = new FileInputStream("/data/" + id);                  // IV-03 #2

        Runtime.getRuntime().exec("ping " + request.getParameter("host"));        // IV-05 #1
        new ProcessBuilder("sh", "-c", id).start();                                // IV-05 #2

        response.sendRedirect(request.getParameter("next"));                      // IV-07

        URL url = new URL(request.getParameter("url"));                           // IV-12 #1
        new URL("http://internal/" + id).openStream();                            // IV-12 #2

        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + request.getParameter("name") + "</h1>");       // IV-04 #1
        response.getWriter().print(request.getParameter("q"));                    // IV-04 #2

        response.setHeader("X-User", request.getParameter("user"));               // IV-13 #1
        response.addCookie(new Cookie("lang", request.getParameter("lang")));     // IV-13 #2

        String role = request.getParameter("role");
        if (role.equals("admin")) { }                     // IV-15 #1 (동등 비교), CE-01 #1 (직후 역참조)
        boolean admin = Boolean.parseBoolean(request.getParameter("isAdmin"));    // IV-15 #2

        String ua = request.getHeader("User-Agent");
        int len = ua.length();                                                    // CE-01 #2

        Cookie c = new Cookie("session_token", id);
        c.setMaxAge(60 * 60 * 24 * 30);                                           // SF-12

        InetAddress addr = InetAddress.getByName(request.getRemoteAddr());
        if (addr.getHostName().endsWith(".trusted.com")) { }                      // AA-01

        try {
            in.read();
        } catch (IOException e) {
            e.printStackTrace(response.getWriter());                               // EH-01 #1
            response.getWriter().println("Error: " + e.getMessage());              // EH-01 #2
        }
        try { in.close(); } catch (IOException e) { }                              // EH-03
    }

    void crypto(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");                       // SF-04 #1
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");                // SF-04 #2
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(password.getBytes("UTF-8"));                       // SF-14

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);                                                      // SF-07

        String token = Long.toString(new Random().nextLong());                      // SF-08 #1
        double sessionSeed = Math.random();                                        // SF-08 #2
    }

    void files(File file, MultipartFile upload) throws Exception {
        file.setWritable(true, false);                                              // SF-03 #1
        Files.setPosixFilePermissions(file.toPath(),
            java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw-rw-"));  // SF-03 #2

        if (file.exists()) {
            FileInputStream s = new FileInputStream(file);                           // TS-01, CE-02
        }

        upload.transferTo(new File("/uploads/", upload.getOriginalFilename()));     // IV-06
    }

    void xml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();          // IV-08
        dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes()));
    }

    void ldap(DirContext ctx, String user) throws Exception {
        ctx.search("ou=people", "(uid=" + user + ")", new SearchControls());        // IV-10
    }

    void deser(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        Object o = ois.readObject();                                                // CE-05
    }

    void threads(Thread t) {
        t.stop();                                                                   // AA-02
        Thread.dumpStack();                                                         // EN-02
    }

    void security(Object http) throws Exception {
        ((HttpSecurity) http).csrf().disable();                                     // IV-11
        ((HttpSecurity) http).authorizeRequests().antMatchers("/admin/**").permitAll();   // SF-01
    }

    void tls(Object builder) {
        javax.net.ssl.TrustManager tm = new javax.net.ssl.X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }   // SF-11 #1
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }     // SF-11 #2
        };
    }

    Connection conn() throws Exception {
        return DriverManager.getConnection("jdbc:x", "app", "hunter2");             // SF-06 #2
    }
}
