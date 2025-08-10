// src/test/java/dev/kaustubh/burp/llm/ChooseTypeTest.java
package dev.kaustubh.burp.llm;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the chooseType method in BurpExtender.LocalLLMPanel.
 * 
 * This test class verifies that the extension correctly determines the appropriate
 * HTTP parameter type (URL, BODY, JSON, COOKIE) based on request characteristics
 * such as HTTP method, Content-Type header, and existing parameters.
 * 
 * The chooseType method is critical for payload injection - it determines where
 * generated payloads should be placed in the HTTP request.
 */
class ChooseTypeTest {

    /**
     * Tests that GET requests default to URL parameters.
     * GET requests typically use query string parameters, so URL type is preferred.
     */
    @Test
    void chooseType_prefersURL_forGET() {
        BurpExtender.LocalLLMPanel panel = TestUtil.panelWithNullApi();
        HttpRequest req = mock(HttpRequest.class);

        when(req.method()).thenReturn("GET");
        // IMPORTANT: use ParsedHttpParameter here
        ParsedHttpParameter qp = mockParam("q", "x", HttpParameterType.URL);
        when(req.parameters()).thenReturn(List.of(qp));
        when(req.headerValue("Content-Type")).thenReturn(null);

        HttpParameterType t = TestUtil.invokeChooseType(panel, null, req);
        assertEquals(HttpParameterType.URL, t);
    }

    /**
     * Tests that POST requests with JSON content type use JSON parameter type.
     * When Content-Type indicates JSON, payloads should be injected as JSON parameters.
     */
    @Test
    void chooseType_json_forPostJson() {
        BurpExtender.LocalLLMPanel panel = TestUtil.panelWithNullApi();
        HttpRequest req = mock(HttpRequest.class);

        when(req.method()).thenReturn("POST");
        when(req.parameters()).thenReturn(List.of()); // also ParsedHttpParameter list (empty ok)
        when(req.headerValue("Content-Type")).thenReturn("application/json; charset=utf-8");

        HttpParameterType t = TestUtil.invokeChooseType(panel, null, req);
        assertEquals(HttpParameterType.JSON, t);
    }

    /**
     * Tests that POST requests with form content type use BODY parameter type.
     * Form-encoded requests should have payloads injected as body parameters.
     */
    @Test
    void chooseType_body_forPostForm() {
        BurpExtender.LocalLLMPanel panel = TestUtil.panelWithNullApi();
        HttpRequest req = mock(HttpRequest.class);

        when(req.method()).thenReturn("POST");
        when(req.parameters()).thenReturn(List.of());
        when(req.headerValue("Content-Type")).thenReturn("application/x-www-form-urlencoded");

        HttpParameterType t = TestUtil.invokeChooseType(panel, null, req);
        assertEquals(HttpParameterType.BODY, t);
    }

    /**
     * Helper method to create mock ParsedHttpParameter objects for testing.
     * Creates properly configured mocks that behave like real Burp parameters.
     */
    private static ParsedHttpParameter mockParam(String name, String value, HttpParameterType type) {
        ParsedHttpParameter p = mock(ParsedHttpParameter.class);
        when(p.name()).thenReturn(name);
        when(p.value()).thenReturn(value);
        when(p.type()).thenReturn(type);
        return p;
    }
}
