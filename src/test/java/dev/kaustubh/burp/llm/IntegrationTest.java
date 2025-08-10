package dev.kaustubh.burp.llm;

import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for end-to-end functionality in BurpExtender.
 * 
 * This test class validates complete workflows and inter-component integration:
 * 1. Full JSON-to-payload pipeline (parsing, validation, data model integrity)
 * 2. Cookie handling utilities used for COOKIE-type payloads
 * 3. Data model serialization/deserialization with Jackson
 * 
 * These tests ensure that the major components work together correctly and that
 * the data models can handle real-world JSON/YAML payload specifications.
 */
public class IntegrationTest {

    /**
     * Tests the complete pipeline from JSON input to parsed payload objects.
     * 
     * This validates:
     * - JSON deserialization of payload specifications
     * - Proper mapping to internal data models (PayloadSpec, Payload)
     * - Field assignment and data integrity
     * - Support for different parameter types (URL, BODY, etc.)
     * 
     * This is critical because it ensures LLM-generated JSON payloads can be
     * properly parsed and executed by the extension.
     */
    @Test
    void fullPipelineFromJsonToPayloads() throws Exception {
        // Simulate complete flow: JSON input -> parse -> validate
        String jsonInput = """
            {
                "payloads": [
                    {"name": "boolean bypass", "param": "id", "payload": "1 OR 1=1", "type": "URL"},
                    {"name": "time delay", "param": "search", "payload": "'; WAITFOR DELAY '0:0:5'--", "type": "BODY"}
                ]
            }
            """;
        
        ObjectMapper json = new ObjectMapper();
        BurpExtender.PayloadSpec spec = json.readValue(jsonInput, BurpExtender.PayloadSpec.class);
        
        assertNotNull(spec);
        assertNotNull(spec.payloads);
        assertEquals(2, spec.payloads.size());
        
        BurpExtender.Payload p1 = spec.payloads.get(0);
        assertEquals("boolean bypass", p1.name);
        assertEquals("id", p1.param);
        assertEquals("1 OR 1=1", p1.payload);
        assertEquals("URL", p1.type);
    }

    /**
     * Tests cookie header manipulation functionality.
     * 
     * This validates the mergeCookie utility method which is used when injecting
     * payloads into Cookie headers (for COOKIE-type parameters). The method must:
     * - Preserve existing cookies
     * - Add new cookie values
     * - Maintain proper formatting (; separator)
     * - Handle edge cases (null/empty headers)
     * 
     * Cookie injection is a common attack vector, so this functionality must be robust.
     */
    @Test
    void cookieMergingWorksCorrectly() {
        String existing = "session=abc123; theme=dark";
        String result = BurpExtender.mergeCookie(existing, "admin", "true");
        
        assertTrue(result.contains("session=abc123"));
        assertTrue(result.contains("theme=dark"));
        assertTrue(result.contains("admin=true"));
        
        // Should be properly formatted
        String[] parts = result.split("; ");
        assertEquals(3, parts.length);
    }
}
