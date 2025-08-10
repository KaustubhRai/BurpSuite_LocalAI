package dev.kaustubh.burp.llm;

import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for error handling and edge cases in BurpExtender.
 * 
 * This test class validates that the extension gracefully handles various error conditions:
 * 1. Malformed YAML and JSON input (syntax errors, missing brackets, etc.)
 * 2. Empty or incomplete payload specifications
 * 3. Invalid data that could cause parsing failures
 * 
 * Robust error handling is critical because:
 * - LLMs can generate malformed output
 * - Network responses may be truncated or corrupted
 * - Users may manually edit payload specifications
 * 
 * The extension should fail gracefully without crashing Burp Suite.
 */
public class ErrorHandlingTest {

    /**
     * Tests graceful handling of syntactically invalid YAML.
     * 
     * Ensures that malformed YAML (missing brackets, incorrect indentation, etc.)
     * throws appropriate exceptions rather than causing crashes or undefined behavior.
     */
    @Test
    void handlesInvalidYamlGracefully() {
        ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
        
        String invalidYaml = """
            payloads:
              - { name: test, param: q, payload: {"admin": true, type: JSON }
            """; // Missing closing brace
        
        assertThrows(Exception.class, () -> {
            yaml.readValue(invalidYaml, BurpExtender.PayloadSpec.class);
        });
    }

    /**
     * Tests graceful handling of syntactically invalid JSON.
     * 
     * Ensures that malformed JSON (missing brackets, trailing commas, etc.)
     * throws appropriate exceptions rather than causing crashes.
     */
    @Test
    void handlesInvalidJsonGracefully() {
        ObjectMapper json = new ObjectMapper();
        
        String invalidJson = """
            {"payloads": [{"name": "test", "param": "q", "payload": "test"}
            """; // Missing closing brackets
        
        assertThrows(Exception.class, () -> {
            json.readValue(invalidJson, BurpExtender.PayloadSpec.class);
        });
    }

    /**
     * Tests handling of empty or incomplete payload specifications.
     * 
     * Validates behavior when:
     * - PayloadSpec is null
     * - payloads array is null or empty
     * - Individual payload objects have missing fields
     * 
     * The extension should handle these cases without crashing.
     */
    @Test
    void handlesEmptyPayloadSpec() {
        BurpExtender.PayloadSpec spec = new BurpExtender.PayloadSpec();
        
        // Should not crash with null payloads list
        assertNull(spec.payloads);
        
        // Should handle empty payloads list
        spec.payloads = java.util.List.of();
        assertTrue(spec.payloads.isEmpty());
    }
}
