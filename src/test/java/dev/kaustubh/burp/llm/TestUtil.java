package dev.kaustubh.burp.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;

import static org.mockito.Mockito.mock;

/**
 * Utility class providing common test helpers and mocks for BurpExtender tests.
 * 
 * This class centralizes test infrastructure to avoid code duplication across test classes.
 * It provides:
 * 1. Mock creation helpers for Burp API objects
 * 2. Reflection-based method invocation for testing private methods
 * 3. Common test setup patterns
 * 
 * By centralizing these utilities, we ensure consistent test patterns and make
 * it easier to maintain tests when the underlying implementation changes.
 */
final class TestUtil {
    
    /**
     * Creates a LocalLLMPanel with a mocked MontoyaApi for testing.
     * 
     * The panel only uses the API in send/execute paths, so for unit tests
     * of parsing and logic methods, a simple mock is sufficient. This avoids
     * the complexity of setting up a full Burp Suite testing environment.
     */
    static BurpExtender.LocalLLMPanel panelWithNullApi() {
        // The panel only uses api in send/execute paths; for chooseType we can pass a mock.
        MontoyaApi api = mock(MontoyaApi.class);
        return new BurpExtender.LocalLLMPanel(api);
    }

    /**
     * Invokes the private chooseType method via reflection for testing.
     * 
     * This method is critical for determining where payloads should be injected
     * in HTTP requests. Since it's private, we use reflection to test it directly
     * without going through the full UI workflow.
     * 
     * @param panel The LocalLLMPanel instance to test
     * @param fromYaml The type specification from YAML (can be null)
     * @param base The HTTP request to analyze
     * @return The determined HttpParameterType
     */
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
