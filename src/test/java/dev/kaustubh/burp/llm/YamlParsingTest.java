package dev.kaustubh.burp.llm;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for YAML parsing and processing functionality in BurpExtender.LocalLLMPanel.
 * 
 * This test class validates two critical YAML processing methods:
 * 1. extractYaml() - Extracts YAML code blocks from LLM responses (markdown format)
 * 2. fixYamlPayloads() - Repairs common YAML formatting issues, especially unquoted JSON objects
 * 
 * These methods are essential for processing LLM-generated payloads, as LLMs often
 * return YAML in markdown code blocks and may generate invalid YAML syntax that needs fixing.
 */
public class YamlParsingTest {

    /**
     * Helper method to invoke the private extractYaml method via reflection.
     * This method extracts YAML content from markdown-formatted LLM responses.
     */
    private static String callExtractYaml(String text) throws Exception {
        Class<?> c = Class.forName("dev.kaustubh.burp.llm.BurpExtender$LocalLLMPanel");
        Method m = c.getDeclaredMethod("extractYaml", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, text);
    }

    /**
     * Helper method to invoke the private fixYamlPayloads method via reflection.
     * This method repairs common YAML formatting issues like unquoted JSON objects.
     */
    private static String callFixYaml(String text) throws Exception {
        Class<?> c = Class.forName("dev.kaustubh.burp.llm.BurpExtender$LocalLLMPanel");
        Method m = c.getDeclaredMethod("fixYamlPayloads", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, text);
    }

    /**
     * Tests extraction of YAML content from markdown code blocks.
     * LLMs often return YAML wrapped in ```yaml...``` fences, this ensures proper extraction.
     */
    @Test
    void extractsYamlFence() throws Exception {
        String in = "blah\n```yaml\npayloads:\n - {name: a, param: q, payload: \"x\"}\n```\nend";
        String y = callExtractYaml(in);
        assertTrue(y.contains("payloads:"), "should find YAML block");
    }

    /**
     * Tests fixing of unquoted JSON objects in YAML payload values.
     * 
     * LLMs sometimes generate YAML with unquoted JSON objects like:
     *   payload: {"admin": true}
     * 
     * This should be fixed to properly quoted and escaped:
     *   payload: "{\"admin\": true}"
     * 
     * This is critical because unquoted JSON objects make YAML invalid and unparseable.
     */
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
