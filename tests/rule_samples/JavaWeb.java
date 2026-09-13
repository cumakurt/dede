// Static-only security regression samples; never execute this class.
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;

class JavaWeb {
    void sql(HttpServletRequest req, Connection conn, Statement stmt) throws Exception {
        String name = req.getParameter("name");
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        // ruleid: dede.java.web.sql-injection
        stmt.executeQuery(query);
        // ruleid: dede.java.web.sql-injection
        conn.prepareStatement(query);
        // ok: dede.java.web.sql-injection
        PreparedStatement safe = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        safe.setString(1, name);
        // ok: dede.java.web.sql-injection
        safe.executeQuery();
    }

    void commands(HttpServletRequest req) throws Exception {
        String command = req.getParameter("cmd");
        // ruleid: dede.java.web.command-injection
        Runtime.getRuntime().exec(command);
        // ok: dede.java.web.command-injection
        Runtime.getRuntime().exec("/usr/bin/uptime");
    }

    void deserialize(HttpServletRequest req) throws Exception {
        ObjectInputStream objects = new ObjectInputStream(req.getInputStream());
        // ruleid: dede.java.web.unsafe-deserialization
        objects.readObject();
        // ok: dede.java.web.unsafe-deserialization
        req.getInputStream().read();
    }

    void xml(DocumentBuilderFactory factory, XMLInputFactory stream) throws Exception {
        // ruleid: dede.java.web.xxe-enabled
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        // ruleid: dede.java.web.xxe-enabled
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        // ruleid: dede.java.web.xxe-enabled
        stream.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
        // ok: dede.java.web.xxe-enabled
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: dede.java.web.xxe-enabled
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }
}
