package dev.kaustubh.burp.llm;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class JsonParsingTest {
    @Test
    void extractsNonStreamingMessage() {
        String body = """
        {"id":"x","choices":[{"message":{"role":"assistant","content":"```yaml\\npayloads:\\n- {name: t, param: q, payload: \\'1\\'}\\n```"}}]}
        """;
        String msg = BurpExtender.Json.extractMessage(body);
        assertNotNull(msg);
        assertTrue(msg.contains("payloads:"), msg);
    }

    @Test
    void extractsSseDelta() {
        String line = "data: {\"choices\":[{\"delta\":{\"content\":\"chunk\"}}]}";
        String delta = BurpExtender.Json.extractDelta(line);
        assertEquals("chunk", delta);
    }
}
