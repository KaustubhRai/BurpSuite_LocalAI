package dev.kaustubh.burp.llm;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

public class YamlParsingTest {

    private static String callExtractYaml(String text) throws Exception {
        Class<?> c = Class.forName("dev.kaustubh.burp.llm.BurpExtender$LocalLLMPanel");
        Method m = c.getDeclaredMethod("extractYaml", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, text);
    }

    private static String callFixYaml(String text) throws Exception {
        Class<?> c = Class.forName("dev.kaustubh.burp.llm.BurpExtender$LocalLLMPanel");
        Method m = c.getDeclaredMethod("fixYamlPayloads", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, text);
    }

    @Test
    void extractsYamlFence() throws Exception {
        String in = "blah\n```yaml\npayloads:\n - {name: a, param: q, payload: \"x\"}\n```\nend";
        String y = callExtractYaml(in);
        assertTrue(y.contains("payloads:"), "should find YAML block");
    }

    @Test
    void fixesUnquotedJsonPayloads() throws Exception {
        String in = """
            payloads:
              - { name: j, param: p, payload: {"admin": true}, type: JSON }
            """;
        String fixed = callFixYaml(in);

        // More flexible assertion - check that JSON is properly quoted and escaped
        assertTrue(fixed.contains("payload:"), "Should contain payload field");
        assertTrue(fixed.contains("\\\"admin\\\""), "Should have escaped quotes");
        assertTrue(fixed.contains("\"{\\\""), "Should start quoted JSON object");
        assertTrue(fixed.contains("}\""), "Should end quoted JSON object");
    }
}
