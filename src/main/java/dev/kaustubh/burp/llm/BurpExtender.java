package dev.kaustubh.burp.llm;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;   
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * Burp Suite extension that integrates with local LLM APIs to generate and execute security payloads
 */
public class BurpExtender implements BurpExtension {
    private MontoyaApi api;

    /**
     * Extension initialization - sets up UI tab and context menu
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Local LLM Assistant");
        api.logging().logToOutput("[LocalLLM] Initializing...");

        // Create main UI panel and register as a tab
        LocalLLMPanel panel = new LocalLLMPanel(api);
        api.userInterface().registerSuiteTab("Local LLM", panel);

        // Register right-click context menu for capturing requests as seeds
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                JMenuItem item = new JMenuItem(new AbstractAction("Local LLM → Use this request as seed") {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // Try to get request from editor first, then from table selection
                        HttpRequestResponse m = event.messageEditorRequestResponse()
                                .map(editor -> editor.requestResponse()).orElse(null);
                        if (m == null) {
                            List<HttpRequestResponse> items = event.selectedRequestResponses();
                            if (items != null && !items.isEmpty()) m = items.get(0);
                        }
                        if (m == null) {
                            api.logging().logToError("[LocalLLM] Context menu invoked but no message was available.");
                            JOptionPane.showMessageDialog(null,
                                    "Couldn't capture from here. Right-click inside the request editor or select a row.",
                                    "Local LLM", JOptionPane.WARNING_MESSAGE);
                            return;
                        }

                        // Set the captured request as seed and prefill with example payload prompt
                        panel.setSeed(m);
                        String prefilled = """
                                Return only a single fenced YAML block.
                                payloads:
                                  - { name: "boolean true", param: q, payload: "' OR '1'='1' --", type: URL }
                                  - { name: "time delay",   param: q, payload: "'; WAITFOR DELAY '0:0:05'--", type: URL }
                                """;
                        panel.setPrompt(prefilled);
                        api.logging().logToOutput("[LocalLLM] Seed set.");
                    }
                });
                return List.of(item);
            }
        });

        api.logging().logToOutput("[LocalLLM] Loaded");
    }

    // ========================= MAIN UI PANEL =========================
    
    /**
     * Main UI panel containing LLM settings, prompt input, and payload execution controls
     */
    static class LocalLLMPanel extends JPanel {
        private final MontoyaApi api;
        
        // LLM API configuration fields
        private final JTextField baseUrlField = new JTextField("http://127.0.0.1:11434/v1/chat/completions");
        private final JTextField modelField = new JTextField("deepseek-r1:14b");
        private final JSpinner tempSpinner = new JSpinner(new SpinnerNumberModel(0.2, 0.0, 2.0, 0.1));
        private final JSpinner maxTokSpinner = new JSpinner(new SpinnerNumberModel(2048, 128, 32768, 128));

        // Feature toggle checkboxes
        private final JCheckBox streamBox = new JCheckBox("Stream", true);
        private final JCheckBox yamlOnlyBox = new JCheckBox("Payloads only (YAML)", true);
        private final JCheckBox stripThinkBox = new JCheckBox("Strip <think>", true);
        private final JCheckBox debugBox = new JCheckBox("Debug lines", false);
        private final JCheckBox fireBox = new JCheckBox("Send via Burp", true);
        private final JCheckBox repeaterBox = new JCheckBox("Also add to Repeater", false);

        // UI components for input/output
        private final JLabel seedLabel = new JLabel("Seed: <none>");
        private final JTextArea promptArea = new JTextArea(12, 120);
        private final JTextArea outArea = new JTextArea(22, 120);
        private final JButton sendBtn = new JButton("Send");

        // HTTP client for LLM API calls
        private final HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .version(HttpClient.Version.HTTP_1_1)
                .build();

        // YAML parser for payload specifications
        private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
        private HttpRequestResponse seed; // The base request to modify with payloads

        /**
         * Constructs the UI layout with settings, prompt area, and output area
         */
        LocalLLMPanel(MontoyaApi api) {
            super(new BorderLayout());
            this.api = api;

            // Configure text areas
            promptArea.setLineWrap(true);
            promptArea.setWrapStyleWord(true);
            outArea.setEditable(false);
            outArea.setLineWrap(true);
            outArea.setWrapStyleWord(true);

            // Build settings panel with GridBag layout
            JPanel settings = new JPanel(new GridBagLayout());
            settings.setBorder(new EmptyBorder(8,8,8,8));
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(4,4,4,4);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 0;

            int row = 0;
            c.gridx = 0; c.gridy = row; settings.add(new JLabel("Base URL"), c);
            c.gridx = 1; c.gridy = row++; c.weightx = 1; settings.add(baseUrlField, c);

            c.weightx = 0; c.gridx = 0; c.gridy = row; settings.add(new JLabel("Model"), c);
            c.gridx = 1; c.gridy = row++; c.weightx = 1; settings.add(modelField, c);

            c.gridx = 0; c.gridy = row; settings.add(new JLabel("Temperature"), c);
            c.gridx = 1; c.gridy = row++; settings.add(tempSpinner, c);

            c.gridx = 0; c.gridy = row; settings.add(new JLabel("Max Tokens"), c);
            c.gridx = 1; c.gridy = row++; settings.add(maxTokSpinner, c);

            // Checkbox options panel
            JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
            opts.add(streamBox);
            opts.add(yamlOnlyBox);
            opts.add(stripThinkBox);
            opts.add(debugBox);
            opts.add(fireBox);
            opts.add(repeaterBox);

            // Assemble top section (settings + prompt input + options)
            JPanel top = new JPanel(new BorderLayout(0,6));
            top.add(settings, BorderLayout.NORTH);
            top.add(new JScrollPane(promptArea), BorderLayout.CENTER);
            top.add(opts, BorderLayout.SOUTH);

            // Assemble bottom section (seed info + output + send button)
            JPanel bottom = new JPanel(new BorderLayout());
            bottom.add(seedLabel, BorderLayout.NORTH);
            bottom.add(new JScrollPane(outArea), BorderLayout.CENTER);

            JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            actions.add(sendBtn);
            bottom.add(actions, BorderLayout.SOUTH);

            add(top, BorderLayout.NORTH);
            add(bottom, BorderLayout.CENTER);

            sendBtn.addActionListener(e -> sendPromptAndMaybeFire());
        }

        // Setter methods for external components
        void setSeed(HttpRequestResponse seed) {
            this.seed = seed;
            String scheme = seed.request().httpService().secure() ? "https" : "http";
            String host = seed.request().httpService().host();
            int port = seed.request().httpService().port();
            seedLabel.setText("Seed: " + seed.request().method() + " " + seed.request().path()
                    + "  @ " + scheme + "://" + host + ":" + port);
        }

        void setPrompt(String p) { promptArea.setText(p); }

        // Getter methods for UI field values
        private String baseUrl() { return baseUrlField.getText().trim(); }
        private String model() { return modelField.getText().trim(); }
        private double temperature() { return ((Number) tempSpinner.getValue()).doubleValue(); }
        private int maxTokens() { return ((Number) maxTokSpinner.getValue()).intValue(); }

        // Helper to append text to output area and scroll to bottom
        private void appendOut(String s) {
            outArea.append(s);
            outArea.setCaretPosition(outArea.getDocument().getLength());
        }

        // ========================= LLM API COMMUNICATION =========================
        
        /**
         * Sends prompt to LLM API and processes response (streaming or non-streaming)
         * If YAML payloads are received and firing is enabled, executes them via Burp
         */
        private void sendPromptAndMaybeFire() {
            String url = baseUrl();
            String model = model();
            String user = promptArea.getText();
            boolean stream = streamBox.isSelected();

            if (user.isBlank()) {
                JOptionPane.showMessageDialog(this, "Prompt is empty", "Local LLM", JOptionPane.WARNING_MESSAGE);
                return;
            }

            appendOut("\n=== Request @ " + java.time.LocalTime.now() + " ===\n");
            appendOut("Model: " + model + "\n");

            // Set system message based on YAML-only mode
            String sys = yamlOnlyBox.isSelected()
                    ? "You are a payload generator. Return only one fenced YAML block with key 'payloads'. "
                      + "Each item: {name, param, payload, type?} where type ∈ {URL,BODY,JSON,COOKIE}. "
                      + "IMPORTANT: All payload values must be quoted strings, even if they contain JSON. "
                      + "Example: payload: '{\"admin\": true}'. No prose."
                    : "You are a senior appsec engineer. Keep answers concise.";

            try {
                // Build OpenAI-compatible chat completion request
                String body = "{"
                        + "\"model\":\"" + escape(model) + "\","
                        + "\"messages\":["
                        + "{\"role\":\"system\",\"content\":\"" + escape(sys) + "\"},"
                        + "{\"role\":\"user\",\"content\":\"" + escape(user) + "\"}"
                        + "],"
                        + "\"temperature\":" + temperature() + ","
                        + "\"max_tokens\":" + maxTokens() + ","
                        + "\"stream\":" + stream
                        + "}";

                java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(120))
                        .header("Content-Type", "application/json")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                        .build();

                if (stream) {
                    // Handle streaming response (Server-Sent Events)
                    http.sendAsync(req, BodyHandlers.ofLines())
                            .thenAccept(resp -> {
                                appendOut("[HTTP " + resp.statusCode() + "]\n");
                                StringBuilder all = new StringBuilder();
                                resp.body().forEach(line -> {
                                    if (line == null || line.isBlank()) return;
                                    String json = line.startsWith("data:") ? line.substring(5).trim() : line.trim();
                                    if ("[DONE]".equals(json)) return;
                                    String delta = Json.extractDelta(json);
                                    if (delta == null) return;
                                    if (stripThinkBox.isSelected()) delta = stripThink(delta);
                                    all.append(delta);
                                });
                                handleModelOutput(all.toString());
                            })
                            .exceptionally(ex -> { appendOut("\n[Error] " + ex + "\n"); return null; });
                } else {
                    // Handle non-streaming response
                    http.sendAsync(req, BodyHandlers.ofString())
                            .thenAccept(resp -> {
                                appendOut("[HTTP " + resp.statusCode() + "]\n");
                                String text = Json.extractMessage(resp.body());
                                if (text == null) text = resp.body();
                                if (stripThinkBox.isSelected()) text = stripThink(text);
                                handleModelOutput(text);
                            })
                            .exceptionally(ex -> { appendOut("\n[Error] " + ex + "\n"); return null; });
                }
            } catch (Exception ex) {
                appendOut("\n[Error building request] " + ex.getMessage() + "\n");
            }
        }

        /**
         * Processes LLM output - extracts YAML if in payload mode, fires payloads if enabled
         */
        private void handleModelOutput(String text) {
            String y = extractYaml(text);
            if (yamlOnlyBox.isSelected()) {
                if (y == null || y.isBlank()) {
                    appendOut("\n[parse] No YAML block found.\n");
                    return;
                }
                appendOut("\n" + y + "\n");
                if (fireBox.isSelected()) fireFromYaml(y);
            } else {
                appendOut("\n" + text + "\n");
            }
        }

        // ========================= PAYLOAD EXECUTION =========================
        
        /**
         * Parses YAML payload specification and executes each payload via Burp HTTP API
         */
        private void fireFromYaml(String yamlText) {
            if (seed == null) {
                appendOut("[fire] No seed selected. Right-click a request → Local LLM → Use this request as seed.\n");
                return;
            }
            if (debugBox.isSelected()) appendOut("[debug] Parsing YAML:\n" + yamlText + "\n");

            try {
                PayloadSpec spec = yaml.readValue(yamlText, PayloadSpec.class);
                if (spec == null || spec.payloads == null || spec.payloads.isEmpty()) {
                    appendOut("[fire] YAML parsed but no payloads found.\n");
                    return;
                }
                processPayloads(spec);
            } catch (Exception ex) {
                appendOut("[fire] YAML parse/send error: " + ex + "\n");
                if (debugBox.isSelected()) {
                    ex.printStackTrace();
                    appendOut("[debug] Attempting to fix YAML...\n");
                }
                // Attempt to fix common YAML formatting issues
                try {
                    String fixedYaml = fixYamlPayloads(yamlText);
                    if (debugBox.isSelected()) appendOut("[debug] Fixed YAML:\n" + fixedYaml + "\n");
                    PayloadSpec spec = yaml.readValue(fixedYaml, PayloadSpec.class);
                    if (spec != null && spec.payloads != null && !spec.payloads.isEmpty()) {
                        appendOut("[fire] Successfully parsed fixed YAML with " + spec.payloads.size() + " payload(s).\n");
                        processPayloads(spec);
                        return;
                    }
                } catch (Exception ex2) {
                    appendOut("[fire] Fixed YAML also failed: " + ex2.getMessage() + "\n");
                }
            }
        }

        /**
         * Executes each payload by modifying the seed request and sending via Burp
         */
        private void processPayloads(PayloadSpec spec) {
            HttpRequest base = seed.request(); // Burp request
            Http httpApi = api.http();
            Repeater repeater = api.repeater();

            if (debugBox.isSelected()) {
                appendOut("[debug] Base: " + base.method() + " " + base.path() + "\n");
            }

            appendOut("[fire] " + spec.payloads.size() + " payload(s). Sending via Burp…\n");

            for (Payload p : spec.payloads) {
                String name = nz(p.name, p.param);
                String param = p.param;
                String value = p.payload;

                HttpRequest mutated = base;

                // Handle cookie parameters specially (merge into Cookie header)
                if ("COOKIE".equalsIgnoreCase(String.valueOf(p.type))) {
                    String current = mutated.headerValue("Cookie");
                    String merged = BurpExtender.mergeCookie(current, param, value);
                    mutated = mutated.withHeader("Cookie", merged);
                } else {
                    // Handle URL/BODY/JSON parameters via Burp's parameter API
                    HttpParameterType type = chooseType(p.type, base);
                    HttpParameter hp = HttpParameter.parameter(param, value, type);
                    mutated = base.withParameter(hp); // add or update
                }

                if (debugBox.isSelected()) {
                    appendOut(String.format("[debug] %s -> %s (%s)\n", name, param,
                            p.type == null ? "AUTO" : p.type));
                }

                // Send the modified request and measure response time
                long t0 = System.nanoTime();
                HttpRequestResponse rr = httpApi.sendRequest(mutated);
                long dtMs = (System.nanoTime() - t0) / 1_000_000;

                // Log response details
                HttpResponse r = rr.response();
                int sc = (r == null) ? -1 : r.statusCode();
                int blen = (r == null || r.body() == null) ? 0 : r.body().length();

                appendOut(String.format("  - %s (%s.%s) => %d %dB %dms\n",
                        name, param, (p.type == null ? "AUTO" : p.type), sc, blen, dtMs));

                // Optionally send to Repeater for manual testing
                if (repeaterBox.isSelected()) {
                    repeater.sendToRepeater(mutated, "LLM/" + name);
                }
            }

            appendOut("[fire] Done.\n");
        }

        // Helper method to use first non-blank string
        private static String nz(String a, String b) { return (a != null && !a.isBlank()) ? a : b; }

        /**
         * Determines appropriate parameter type based on YAML spec or request characteristics
         */
        private HttpParameterType chooseType(String fromYaml, HttpRequest base) {
            // Use YAML-specified type if valid
            if (fromYaml != null) {
                try { return HttpParameterType.valueOf(fromYaml.trim().toUpperCase(Locale.ROOT)); }
                catch (IllegalArgumentException ignore) {}
            }
            
            // Auto-detect based on HTTP method and content type
            String method = Optional.ofNullable(base.method()).orElse("GET").toUpperCase(Locale.ROOT);
            if (method.equals("GET") || method.equals("HEAD")) return HttpParameterType.URL;

            String ct = Optional.ofNullable(base.headerValue("Content-Type")).orElse("").toLowerCase(Locale.ROOT);
            if (ct.contains("application/json")) return HttpParameterType.JSON;
            if (ct.contains("application/x-www-form-urlencoded")) return HttpParameterType.BODY;

            // Fallback: keep existing parameter style or default to BODY
            if (hasAnyParam(base, HttpParameterType.URL)) return HttpParameterType.URL;
            return HttpParameterType.BODY;
        }

        private static boolean hasAnyParam(HttpRequest req, HttpParameterType type) {
            for (HttpParameter p : req.parameters()) if (p.type() == type) return true;
            return false;
        }

        // ========================= TEXT PROCESSING UTILITIES =========================
        
        /**
         * Removes <think> tags from LLM output (for reasoning models)
         */
        private static String stripThink(String s) {
            String out = s.replaceAll("(?is)<think>.*?</think>", "");
            out = out.replace("\\u003cthink\\u003e", "").replace("\\u003c/think\\u003e", "");
            return out;
        }

        /**
         * Extracts YAML code block from markdown-formatted text
         */
        private static String extractYaml(String text) {
            // Look for ```yaml blocks
            int last = -1, start = -1, end = -1, idx = 0;
            while (true) {
                int s1 = text.indexOf("```yaml", idx);
                if (s1 < 0) break;
                int s2 = text.indexOf('\n', s1);
                int e  = text.indexOf("```", Math.max(s2, s1 + 6));
                if (e > 0) { last = s1; start = s2 + 1; end = e; }
                idx = s1 + 6;
            }
            if (last >= 0) return text.substring(start, end).trim();
            
            // Fallback: look for any ``` blocks
            int s = text.indexOf("```");
            if (s >= 0) {
                int e = text.indexOf("```", s + 3);
                if (e > s) return text.substring(s + 3, e).trim();
            }
            return null;
        }

        /**
         * Attempts to fix common YAML formatting issues (JSON objects in payload values)
         */
        private static String fixYamlPayloads(String yamlText) {
            String[] lines = yamlText.split("\n");
            StringBuilder fixed = new StringBuilder();
            for (String line : lines) {
                if (line.contains("payload:") && line.contains("{") && line.contains("}")) {
                    int i = line.indexOf("payload:");
                    String before = line.substring(0, i + 8);
                    String after = line.substring(i + 8).trim();
                    if ((after.startsWith("{") && after.endsWith("}")) ||
                        (after.startsWith("[") && after.endsWith("]"))) {
                        String escaped = after.replace("\"", "\\\"");
                        fixed.append(before).append("\"").append(escaped).append("\"\n");
                    } else fixed.append(line).append("\n");
                } else fixed.append(line).append("\n");
            }
            return fixed.toString();
        }

        /**
         * Escapes strings for JSON encoding
         */
        private static String escape(String s) {
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
        }
    }

    // ========================= DATA MODELS =========================
    
    /**
     * YAML payload specification - contains list of payload objects
     */
    public static class PayloadSpec { public List<Payload> payloads; }
    
    /**
     * Individual payload definition with name, parameter, value, and type
     */
    public static class Payload { public String name; public String param; public String payload; public String type; }

    // ========================= COOKIE UTILITIES =========================
    
    /**
     * Merges a new cookie value into existing Cookie header string
     */
    static String mergeCookie(String cookieHeader, String name, String value) {
        Map<String,String> map = new LinkedHashMap<>();
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            for (String part : cookieHeader.split(";\\s*")) {
                int eq = part.indexOf('=');
                if (eq > 0) map.put(part.substring(0, eq), part.substring(eq + 1));
            }
        }
        map.put(name, value);
        return map.entrySet().stream()
            .map(e -> e.getKey() + "=" + e.getValue())
            .collect(Collectors.joining("; "));
    }

    // ========================= JSON PARSING UTILITIES =========================
    
    /**
     * Minimal JSON parser for extracting content from OpenAI API responses
     */
    static class Json {
        /**
         * Extracts message content from chat completion response
         */
        static String extractMessage(String body) {
            try {
                int idx = body.indexOf("\"message\"");
                if (idx < 0) return null;
                int c = body.indexOf("\"content\"", idx);
                if (c < 0) return null;
                int start = body.indexOf('"', c + 9);
                if (start < 0) return null;
                int end = findStringEnd(body, start + 1);
                if (end < 0) return null;
                return unescape(body.substring(start + 1, end));
            } catch (Exception e) { return null; }
        }
        
        /**
         * Extracts delta content from streaming response line
         */
        static String extractDelta(String line) {
            int d = line.indexOf("\"delta\"");
            if (d < 0) return null;
            int c = line.indexOf("\"content\"", d);
            if (c < 0) return null;
            int start = line.indexOf('"', c + 9);
            if (start < 0) return null;
            int end = findStringEnd(line, start + 1);
            if (end < 0) return null;
            return unescape(line.substring(start + 1, end));
        }
        
        /**
         * Finds the end of a JSON string, handling escape sequences
         */
        private static int findStringEnd(String s, int from) {
            boolean esc = false;
            for (int i = from; i < s.length(); i++) {
                char ch = s.charAt(i);
                if (esc) { esc = false; continue; }
                if (ch == '\\') { esc = true; continue; }
                if (ch == '"') return i;
            }
            return -1;
        }
        
        /**
         * Unescapes basic JSON string escape sequences
         */
        private static String unescape(String s) {
            return s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
        }
    }
}
