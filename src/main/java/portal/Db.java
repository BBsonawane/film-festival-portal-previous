package portal;

import java.sql.*;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

@WebListener
public class Db implements ServletContextListener {
    static Connection c() throws Exception {
        Class.forName("com.mysql.cj.jdbc.Driver");
        var env = System.getenv();
        return DriverManager.getConnection(
            env.getOrDefault("DB_URL", "jdbc:mysql://localhost:3306/filmfest?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true"),
            env.getOrDefault("DB_USER", "root"), env.getOrDefault("DB_PASS", ""));
    }

    @Override public void contextInitialized(ServletContextEvent ev) {
        try (var in = Db.class.getResourceAsStream("/schema.sql"); Connection c = c(); Statement st = c.createStatement()) {
            for (String sql : new String(in.readAllBytes()).split(";")) if (!sql.isBlank()) st.execute(sql);
        } catch (Exception ex) { throw new RuntimeException("Database setup failed", ex); }
    }
}
