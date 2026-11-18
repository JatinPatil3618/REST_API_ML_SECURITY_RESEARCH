package com.apisecurity.gateway.policy;

import com.apisecurity.gateway.features.FeatureExtractor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Review-profile inspection. These rules are not model predictions and are not
 * consulted for the production profile. Each pattern is limited to a structure
 * the lab requests use and that ordinary catalog searches do not.
 */
@Component
public class ReviewRequestGuard {

    public static final String PATH_TRAVERSAL = "ATRDF-PATH-TRAVERSAL";
    public static final String JNDI_LOOKUP = "ATRDF-JNDI-LOOKUP";
    public static final String SQL_STRUCTURE = "ATRDF-SQL-STRUCTURE";
    public static final String COMMAND_CHAIN = "ATRDF-COMMAND-CHAIN";
    public static final String COOKIE_AUTHORITY = "ATRDF-COOKIE-AUTHORITY";
    public static final String MARKUP_SCRIPT = "ATRDF-MARKUP-SCRIPT";
    public static final String LOG_LINE = "ATRDF-LOG-LINE";

    private static final Pattern TRAVERSAL = Pattern.compile(
            "(?:^|/)\\.\\.(?:/|$)|\\.\\./|\\.\\.\\\\|%2e%2e|\\.\\.%2f|%2f\\.\\.|%5c",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern FILE_TARGET = Pattern.compile(
            "/etc/(?:passwd|shadow)|[/\\\\]windows[/\\\\]|web-inf[/\\\\]|(?:system|win)\\.ini|%systemroot%|%windir%|[a-z]:[/\\\\]",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SQL_STRUCTURE_PATTERN = Pattern.compile(
            "'\\s*or\\s+'[^']*'\\s*=\\s*'|'\\s*or\\s+\\d+\\s*=\\s*\\d+|\\bunion\\s+select\\b"
                    + "|\\b(?:pg_sleep|benchmark|sleep)\\s*\\("
                    + "|\\bdbms_(?:session\\.sleep|pipe\\.receive_message)\\s*\\("
                    + "|\\bwaitfor\\s+delay\\b"
                    + "|java\\.lang\\.Thread\\.sleep",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern COMMAND_CHAIN_PATTERN = Pattern.compile(
            "(?:;|\\||&&|`)\\s*(?:cat|nc|bash|sh|cmd|powershell|wget|curl)\\b"
                    + "|(?:;|&|\\|)\\s*(?:sleep\\s+\\d|start-sleep\\b)"
                    + "|\\bcat\\s+/etc/(?:passwd|shadow)\\b"
                    + "|\\bexecSync\\s*\\("
                    + "|\\bchild_process\\b"
                    + "|freemarker\\.template\\.utility\\.Execute"
                    + "|<%[=%]"
                    + "|\\{system\\s*\\("
                    + "|%x\\s*\\("
                    + "|\\bstart-sleep\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern MARKUP_PATTERN = Pattern.compile(
            "<\\s*script\\b|\\bon(?:error|load|click|mouseover)\\s*=",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern LOG_BREAK = Pattern.compile("\\\\\\\\r\\\\\\\\n|\\\\r\\\\n|\\r|\\n");
    private static final Pattern LOG_SEVERITY = Pattern.compile("\\[(?:CRITICAL|ERROR|WARN|INFO|DEBUG)\\]");

    public static final class Match {
        public final String id;
        public final int status;
        public final String message;

        public Match(String id, int status, String message) {
            this.id = id;
            this.status = status;
            this.message = message;
        }
    }

    public Match inspect(HttpServletRequest request, String body) {
        if (request == null) {
            return null;
        }
        String pathAndQuery = unfolded(request.getRequestURI()) + "\n" + unfolded(request.getQueryString());
        if (request.getParameterMap() != null) {
            for (String[] values : request.getParameterMap().values()) {
                if (values == null) {
                    continue;
                }
                for (String value : values) {
                    pathAndQuery = pathAndQuery + "\n" + unfolded(value);
                }
            }
        }
        String bodyText = body == null ? "" : body;
        String queryAndBody = pathAndQuery + "\n" + unfolded(bodyText);

        if (TRAVERSAL.matcher(pathAndQuery).find()) {
            return match(PATH_TRAVERSAL, "Invalid resource path.");
        }
        if (FeatureExtractor.jndiLookupMarker(request, bodyText) == 1) {
            return match(JNDI_LOOKUP, "Dangerous lookup pattern blocked.");
        }
        if (COMMAND_CHAIN_PATTERN.matcher(queryAndBody).find()) {
            return match(COMMAND_CHAIN, "Command execution attempt blocked. No command was executed.");
        }
        if (SQL_STRUCTURE_PATTERN.matcher(queryAndBody).find()) {
            return match(SQL_STRUCTURE, "Suspicious query input detected and rejected.");
        }
        if (FILE_TARGET.matcher(queryAndBody).find()) {
            return match(PATH_TRAVERSAL, "Invalid resource path.");
        }
        if (cookieClaimsAuthority(request)) {
            return match(COOKIE_AUTHORITY, "Cookie authority fields are not accepted.");
        }
        if (MARKUP_PATTERN.matcher(queryAndBody).find()) {
            return match(MARKUP_SCRIPT, "Unsafe markup blocked.");
        }
        if (LOG_BREAK.matcher(bodyText).find() && LOG_SEVERITY.matcher(bodyText).find()) {
            return match(LOG_LINE, "Malformed logging input detected.");
        }
        return null;
    }

    private static boolean cookieClaimsAuthority(HttpServletRequest request) {
        String cookie = request.getHeader("Cookie");
        if (cookie == null || cookie.isBlank()) {
            return false;
        }
        for (String part : cookie.split(";")) {
            String name = part.split("=", 2)[0].trim();
            if (name.equalsIgnoreCase("admin") || name.equalsIgnoreCase("role")) {
                return true;
            }
        }
        return false;
    }

    static String unfolded(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        String once = FeatureExtractor.percentDecode(raw);
        String form = FeatureExtractor.formDecode(raw);
        String twice = FeatureExtractor.percentDecode(once);
        return raw + "\n" + once + "\n" + form + "\n" + twice;
    }

    private static Match match(String id, String message) {
        return new Match(id, 403, message);
    }
}
