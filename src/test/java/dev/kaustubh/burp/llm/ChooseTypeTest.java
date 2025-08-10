// src/test/java/dev/kaustubh/burp/llm/ChooseTypeTest.java
package dev.kaustubh.burp.llm;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ChooseTypeTest {

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

    private static ParsedHttpParameter mockParam(String name, String value, HttpParameterType type) {
        ParsedHttpParameter p = mock(ParsedHttpParameter.class);
        when(p.name()).thenReturn(name);
        when(p.value()).thenReturn(value);
        when(p.type()).thenReturn(type);
        return p;
    }
}
