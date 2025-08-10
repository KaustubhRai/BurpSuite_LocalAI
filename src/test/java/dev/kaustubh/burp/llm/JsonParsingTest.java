package dev.kaustubh.burp.llm;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JSON parsing and extraction functionality in BurpExtender.
 * 
 * This test class validates JSON processing methods used for:
 * 1. Extracting JSON payload specifications from LLM responses
 * 2. Parsing OpenAI-compatible API responses (both streaming and non-streaming)
 * 3. Handling markdown-formatted JSON code blocks
 * 
 * These methods are critical for processing LLM responses that contain payload
 * specifications in JSON format, as well as parsing responses from LLM APIs.
 */
public class JsonParsingTest {

    /**
     * Helper method to invoke the private extractJson method via reflection.
     * This method extracts JSON content from markdown-formatted LLM responses.
     */
    private static String callExtractJson(String text) throws Exception {
        Class<?> c = Class.forName("dev.kaustubh.burp.llm.BurpExtender$LocalLLMPanel");
        Method m = c.getDeclaredMethod("extractJson", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, text);
    }

    /**
     * Tests extraction of JSON content from markdown code blocks.
     * LLMs often return JSON wrapped in ```json...``` fences, this ensures proper extraction.
     */
    @Test
    void extractsJsonCodeBlock() throws Exception {
        String input = """
            Here's the response:
            ```json
            {"payloads": [{"name": "test", "param": "q", "payload": "' OR 1=1--"}]}
            ```
            That's it.
            """;
        
        String result = callExtractJson(input);
        assertTrue(result.contains("payloads"));
        assertTrue(result.startsWith("{"));
        assertTrue(result.endsWith("}"));
    }

    /**
     * Tests case-insensitive JSON marker detection.
     * Some LLMs use different cases like ```JSON instead of ```json.
     */
    @Test
    void handlesCaseInsensitiveJsonMarkers() throws Exception {
        String input = "```JSON\n{\"test\": true}\n```";
        String result = callExtractJson(input);
        assertEquals("{\"test\": true}", result);
    }

    /**
     * Tests graceful handling when no JSON block is present.
     * Should return null rather than throwing exceptions.
     */
    @Test
    void returnsNullForNoJsonBlock() throws Exception {
        String input = "No JSON here, just text";
        String result = callExtractJson(input);
        assertNull(result);
    }

    /**
     * Tests handling of multiple JSON blocks.
     * Should extract the last/most recent JSON block when multiple are present.
     */
    @Test
    void handlesMultipleJsonBlocks() throws Exception {
        String input = """
            ```json
            {"first": true}
            ```
            Some text
            ```json  
            {"second": true}
            ```
            """;
        
        String result = callExtractJson(input);
        assertTrue(result.contains("second")); // Should get the last one
    }

    /**
     * Tests extraction of message content from OpenAI-style API responses.
     * Validates parsing of non-streaming chat completion responses.
     */
    @Test
    void extractsNonStreamingMessage() {
        String body = """
        {"id":"x","choices":[{"message":{"role":"assistant","content":"```yaml\\npayloads:\\n- {name: t, param: q, payload: \\'1\\'}\\n```"}}]}
        """;
        String msg = BurpExtender.Json.extractMessage(body);
        assertNotNull(msg);
        assertTrue(msg.contains("payloads:"), msg);
    }

    /**
     * Tests extraction of delta content from Server-Sent Events (streaming responses).
     * Validates parsing of streaming chat completion responses.
     */
    @Test
    void extractsSseDelta() {
        String line = "data: {\"choices\":[{\"delta\":{\"content\":\"chunk\"}}]}";
        String delta = BurpExtender.Json.extractDelta(line);
        assertEquals("chunk", delta);
    }
}
