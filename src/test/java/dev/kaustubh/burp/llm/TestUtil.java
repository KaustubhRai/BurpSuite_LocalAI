package dev.kaustubh.burp.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;

import static org.mockito.Mockito.mock;

final class TestUtil {
    static BurpExtender.LocalLLMPanel panelWithNullApi() {
        // The panel only uses api in send/execute paths; for chooseType we can pass a mock.
        MontoyaApi api = mock(MontoyaApi.class);
        return new BurpExtender.LocalLLMPanel(api);
    }

    static HttpParameterType invokeChooseType(BurpExtender.LocalLLMPanel panel, String fromYaml,
                                              burp.api.montoya.http.message.requests.HttpRequest base) {
        try {
            var m = BurpExtender.LocalLLMPanel.class
                    .getDeclaredMethod("chooseType", String.class,
                            burp.api.montoya.http.message.requests.HttpRequest.class);
            m.setAccessible(true);
            return (HttpParameterType) m.invoke(panel, fromYaml, base);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
