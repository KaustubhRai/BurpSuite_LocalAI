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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.databind.DeserializationFeature;

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

                        // Set the captured request as seed
                        panel.setSeed(m);
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
        private final JTextField baseUrlField = new JTextField("http://127.0.0.1:11434/api/chat");
        private final JTextField modelField = new JTextField("gemma3:4b");
        private final JSpinner tempSpinner = new JSpinner(new SpinnerNumberModel(0.15, 0.0, 2.0, 0.05));
        private final JSpinner maxTokSpinner = new JSpinner(new SpinnerNumberModel(256, 64, 8192, 64));

        // Feature toggle checkboxes
        private final JCheckBox streamBox = new JCheckBox("Stream", false);
        private final JCheckBox yamlOnlyBox = new JCheckBox("Payloads only (YAML)", true);
        private final JCheckBox stripThinkBox = new JCheckBox("Strip <think>", false);
        private final JCheckBox debugBox = new JCheckBox("Debug lines", false);
        private final JCheckBox fireBox = new JCheckBox("Send via Burp", true);
        private final JCheckBox repeaterBox = new JCheckBox("Also add to Repeater", false);

        // command mode: generate from short intent
        private final JCheckBox commandModeBox = new JCheckBox("Command mode", true);
        private final JComboBox<String> familyCombo =
                new JComboBox<>(new String[]{"NoSQL","SQL","XSS","PathTraversal","CommandInjection"});
        private final JComboBox<String> whereCombo =
                new JComboBox<>(new String[]{"URL","BODY","JSON","COOKIE"});
        private final JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 20, 1));

        // Encoding controls
        private final JCheckBox encodeBox = new JCheckBox("Encode variants", false);
        private final JComboBox<String> encodeTypeCombo = new JComboBox<>(new String[]{"URL","Base64","HTML"});

        // UI components for input/output
        private final JLabel seedLabel = new JLabel("Seed: <none>");
        private final JTextArea promptArea = new JTextArea(12, 120);
        private final JTextArea outArea = new JTextArea(22, 120);
        private final JButton sendBtn = new JButton("Send");
        private final JButton clearBtn = new JButton("Clear");
        private volatile long tSendNs = 0L;

        // HTTP client for LLM API calls
        private final HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .version(HttpClient.Version.HTTP_1_1)
                .build();

        // YAML parser for payload specifications
        private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());
        private final ObjectMapper json = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
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

            // Checkbox options panel (split into two rows so nothing is clipped)
            JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
            row1.add(streamBox);
            row1.add(yamlOnlyBox);
            row1.add(stripThinkBox);
            row1.add(debugBox);
            row1.add(fireBox);
            row1.add(repeaterBox);

            JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
            row2.add(new JLabel("Mode:"));
            row2.add(commandModeBox);
            row2.add(new JLabel("Family:"));
            row2.add(familyCombo);
            row2.add(new JLabel("Where:"));
            row2.add(whereCombo);
            row2.add(new JLabel("#:"));
            row2.add(countSpinner);
            row2.add(new JLabel("Encode:"));
            row2.add(encodeBox);
            row2.add(encodeTypeCombo);

            // Enable/disable the encode type selector with the checkbox
            encodeTypeCombo.setEnabled(false);
            encodeBox.addActionListener(ev -> encodeTypeCombo.setEnabled(encodeBox.isSelected()));

            // Parent panel that stacks both rows vertically
            JPanel opts = new JPanel();
            opts.setLayout(new BoxLayout(opts, BoxLayout.Y_AXIS));
            opts.add(row1);
            opts.add(row2);


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
            actions.add(clearBtn);
            actions.add(sendBtn);
            clearBtn.addActionListener(e -> {
                outArea.setText("");
                outArea.setCaretPosition(0);
            });
            bottom.add(actions, BorderLayout.SOUTH);

            add(top, BorderLayout.NORTH);
            add(bottom, BorderLayout.CENTER);

            sendBtn.addActionListener(e -> sendPromptAndMaybeFire());
        }

        private String buildInstructionFromSeed(String userIntent) {
                HttpRequest r = (seed != null) ? seed.request() : null;

                // Gather param names from the seed by location
                List<String> urlParams  = new ArrayList<>();
                List<String> bodyParams = new ArrayList<>();
                List<String> jsonParams = new ArrayList<>();
                List<? extends HttpParameter> seedParams = (r != null) ? r.parameters() : java.util.Collections.emptyList();
                for (HttpParameter p : seedParams) {
                    switch (p.type()) {
                        case URL  -> urlParams.add(p.name());
                        case BODY -> bodyParams.add(p.name());
                        case JSON -> jsonParams.add(p.name());
                        default -> {}
                    }
                }
                // Cookies: just surface names if present
                String cookieHeader = (r != null) ? r.headerValue("Cookie") : null;
                List<String> cookieParams = new ArrayList<>();
                if (cookieHeader != null && !cookieHeader.isBlank()) {
                    for (String part : cookieHeader.split(";\\s*")) {
                        int eq = part.indexOf('=');
                        if (eq > 0) cookieParams.add(part.substring(0, eq));
                    }
                }

                String family = String.valueOf(familyCombo.getSelectedItem());
                String where  = String.valueOf(whereCombo.getSelectedItem());
                int count     = ((Number) countSpinner.getValue()).intValue();

                // Choose allowed param names for the target location
                List<String> allowed = switch (where) {
                    case "URL"    -> urlParams;
                    case "BODY"   -> bodyParams;
                    case "JSON"   -> jsonParams;
                    case "COOKIE" -> cookieParams;
                    default       -> urlParams;
                };
                // If none found, give a sensible default so the model can proceed
                if (allowed.isEmpty()) {
                    allowed = List.of("q","search","id","name");
                }

                // Single, strict instruction the model must follow
                return """
                    Intent: %s

                    Generate exactly %d %s injection probes targeting %s parameters.
                    Use ONLY these parameter names: %s
                    Rules:
                    - Return ONE fenced YAML block and nothing else.
                    - Schema:
                        payloads:
                        - { name: "...", param: <one-of-allowed>, payload: "<string>", type: %s }
                    - Every payload MUST be a quoted string.
                    - Prefer low-noise, high-signal probes (boolean, regex, $ne/$gt/$where for NoSQL; boolean/time for SQL, etc.).
                    """.formatted(
                        userIntent == null || userIntent.isBlank() ? "Generate payloads" : userIntent,
                        count, family, where, allowed, where
                );
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
            SwingUtilities.invokeLater(() -> {
                outArea.append(s);
                outArea.setCaretPosition(outArea.getDocument().getLength());
            });
        }

        // ========================= LLM API COMMUNICATION =========================
        
        /**
         * Sends prompt to LLM API and processes response (streaming or non-streaming)
         * If YAML/JSON payloads are received and firing is enabled, executes them via Burp
         */
        private void sendPromptAndMaybeFire() {
            String url = baseUrl();
            String model = model();
            String promptText = promptArea.getText().trim();
            boolean useCommand = commandModeBox.isSelected() && promptText.isBlank();
            String user = useCommand ? buildInstructionFromSeed("") : promptText;
            boolean stream = streamBox.isSelected();

            if (user.isBlank()) {
                JOptionPane.showMessageDialog(this, "Prompt is empty", "Local LLM", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // mark overall start time
            tSendNs = System.nanoTime();
            appendOut("\n=== Request @ " + java.time.LocalTime.now() + " ===\n");
            appendOut("Model: " + model + "\n");

            // Set system message based on YAML-only mode
            String sys = yamlOnlyBox.isSelected()
                    ? "You are a payload generator. Return ONE fenced block containing a `payloads` array. Prefer JSON, YAML is also acceptable. "
                      + "Schema: { \"payloads\": [ { \"name\": \"...\", \"param\": \"...\", \"payload\": \"...\", \"type\": \"URL|BODY|JSON|COOKIE\" } ] }. "
                      + "STRICT: Use DOUBLE quotes for all strings. Do not escape single quotes with backslashes. No prose, no prefix/suffix."
                    : "You are a senior appsec engineer. Keep answers concise.";

            try {
                // Build OpenAI-compatible chat completion request
                String body;
                boolean usingOllama = baseUrl().contains("/api/");  // native Ollama if true
                if (usingOllama) {
                    body = "{"
                        + "\"model\":\"" + escape(model) + "\","
                        + "\"stream\":" + stream + ","
                        + "\"messages\":["
                        + "{\"role\":\"system\",\"content\":\"" + escape(sys) + "\"},"
                        + "{\"role\":\"user\",\"content\":\"" + escape(user) + "\"}"
                        + "],"
                        + "\"options\":{"
                        + "\"temperature\":" + temperature() + ","
                        + "\"num_predict\":" + maxTokens()
                        + "}"
                        + "}";
                } else {
                    body = "{"
                        + "\"model\":\"" + escape(model) + "\","
                        + "\"messages\":["
                        + "{\"role\":\"system\",\"content\":\"" + escape(sys) + "\"},"
                        + "{\"role\":\"user\",\"content\":\"" + escape(user) + "\"}"
                        + "],"
                        + "\"temperature\":" + temperature() + ","
                        + "\"max_tokens\":" + maxTokens() + ","
                        + "\"stream\":" + stream
                        + "}";
                }

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
                                String raw = resp.body();
                                if (resp.statusCode() >= 400) {
                                    appendOut("[error-body] " + raw + "\n");
                                }
                                String text = Json.extractMessage(raw);
                                if (text == null) text = raw;
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
         * Processes LLM output - extracts JSON or YAML if in payload mode, fires payloads if enabled
         */
        private void handleModelOutput(String text) {
            if (!yamlOnlyBox.isSelected()) {
                appendOut("\n" + text + "\n");
                return;
            }
            // Try JSON first (more robust), then YAML, then raw fallbacks and repairs.
            try {
                String block = extractJson(text);
                boolean usedJson = true;
                if (block == null) {
                    block = extractYaml(text);
                    usedJson = false;
                }
                PayloadSpec spec = null;
                String printed = null;

                if (block != null) {
                    printed = block;
                    try {
                        spec = usedJson ? json.readValue(block, PayloadSpec.class)
                                        : yaml.readValue(block, PayloadSpec.class);
                    } catch (Exception ex1) {
                        if (!usedJson) {
                            // Attempt to repair common YAML quoting issues (e.g., single-quoted with backslashes)
                            String repaired = fixYamlWeirdQuotes(block);
                            try { 
                                spec = yaml.readValue(repaired, PayloadSpec.class); 
                                printed = repaired;
                            } catch (Exception ignore) { /* keep going to other fallbacks */ }
                        }
                    }
                }

                // Fallback: whole response as JSON?
                if (spec == null) {
                    String t = text.trim();
                    if (t.startsWith("{") && t.endsWith("}")) {
                        try { spec = json.readValue(t, PayloadSpec.class); printed = t; } catch (Exception ignore) {}
                    }
                }

                // Fallback: whole response as YAML?
                if (spec == null) {
                    try { spec = yaml.readValue(text, PayloadSpec.class); printed = text; }
                    catch (Exception ex2) {
                        // Try a last repair pass on entire text
                        String repaired = fixYamlWeirdQuotes(text);
                        try { spec = yaml.readValue(repaired, PayloadSpec.class); printed = repaired; }
                        catch (Exception ex3) {
                            appendOut("\n[parse] Could not parse JSON/YAML payloads. Last error: " + ex3.getMessage() + "\n");
                            return;
                        }
                    }
                }

                // If we got here, we have a spec
                appendOut("\n" + (printed == null ? "" : printed) + "\n");
                if (fireBox.isSelected()) fireFromSpec(spec);
            } catch (Exception e) {
                appendOut("\n[parse] Unexpected parse error: " + e + "\n");
            }
        }

        /**
         * Fires payloads from a parsed PayloadSpec (JSON/YAML)
         */
        private void fireFromSpec(PayloadSpec spec) {
            if (spec == null || spec.payloads == null || spec.payloads.isEmpty()) {
                appendOut("[fire] No payloads to send.\n");
                return;
            }
            processPayloads(spec);
        }

        // ========================= PAYLOAD EXECUTION =========================
        
        /**
         * Parses YAML payload specification and executes each payload via Burp HTTP API (delegates to fireFromSpec)
         */
        private void fireFromYaml(String yamlText) {
            if (seed == null) {
                appendOut("[fire] No seed selected. Right-click a request → Local LLM → Use this request as seed.\n");
                return;
            }
            if (debugBox.isSelected()) appendOut("[debug] Parsing (YAML-preferred) block…\n");
            try {
                // Try YAML first
                PayloadSpec spec = null;
                try {
                    spec = yaml.readValue(yamlText, PayloadSpec.class);
                } catch (Exception first) {
                    // Try repair then JSON
                    try {
                        String fixed = fixYamlWeirdQuotes(yamlText);
                        spec = yaml.readValue(fixed, PayloadSpec.class);
                    } catch (Exception second) {
                        spec = json.readValue(yamlText, PayloadSpec.class);
                    }
                }
                fireFromSpec(spec);
            } catch (Exception ex) {
                appendOut("[fire] Parse failed: " + ex.getMessage() + "\n");
            }
        }

        /**
         * Executes each payload by modifying the seed request and sending via Burp
         */
        private void processPayloads(PayloadSpec spec) {
            // Fan-out degree; you can tune this (6–8 is a good start)
            final int MAX_PAR = 6;

            HttpRequest base = seed.request();
            Http httpApi = api.http();
            Repeater repeater = api.repeater();

            if (debugBox.isSelected()) {
                appendOut("[debug] Base: " + base.method() + " " + base.path() + "\n");
            }

            long fireStartNs = System.nanoTime();
            appendOut("[fire] " + spec.payloads.size() + " payload(s). Sending via Burp in parallel…\n");

            // Determine encoding selection once
            final boolean doEncode = encodeBox.isSelected();
            final String encKind = doEncode ? String.valueOf(encodeTypeCombo.getSelectedItem()) : null;

            // Build tasks up-front
            java.util.List<Callable<String>> tasks = new java.util.ArrayList<>();
            for (Payload p : spec.payloads) {
                // Build variants: normal + encoded (if selected)
                java.util.List<String[]> variants = new java.util.ArrayList<>();
                variants.add(new String[] {"", p.payload}); // normal
                if (doEncode) {
                    variants.add(new String[] {" [enc=" + encKind + "]", encodeValue(p.payload, encKind)});
                }

                for (String[] vv : variants) {
                    final String nameSuffix = vv[0];
                    final String valueVariant = vv[1];

                    tasks.add(() -> {
                        String name = nz(p.name, p.param) + nameSuffix;
                        String param = saneParamName(p.param) ? p.param : chooseFallbackParam(base, String.valueOf(p.type));
                        String value = valueVariant;

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
                            mutated = base.withParameter(hp);
                        }

                        // Send the modified request and measure response time
                        long t0 = System.nanoTime();
                        HttpRequestResponse rr = httpApi.sendRequest(mutated);
                        long dtMs = (System.nanoTime() - t0) / 1_000_000;

                        // Log response details
                        HttpResponse r = rr.response();
                        int sc = (r == null) ? -1 : r.statusCode();
                        int blen = (r == null || r.body() == null) ? 0 : r.body().length();

                        if (repeaterBox.isSelected()) {
                            repeater.sendToRepeater(mutated, "LLM/" + name);
                        }

                        return String.format("  - %s (%s.%s) => %d %dB %dms\n",
                                name, param, (p.type == null ? "AUTO" : p.type), sc, blen, dtMs);
                    });
                }
            }

            // Run tasks off-EDT
            java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(MAX_PAR);
            try {
                java.util.List<java.util.concurrent.Future<String>> futures = pool.invokeAll(tasks);
                for (java.util.concurrent.Future<String> f : futures) {
                    try {
                        appendOut(f.get());
                    } catch (Exception ex) {
                        appendOut("  - [error] " + ex + "\n");
                    }
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                appendOut("[fire] interrupted\n");
            } finally {
                pool.shutdown();
            }

            long fireMs = (System.nanoTime() - fireStartNs) / 1_000_000;
            long totalMs = (System.nanoTime() - tSendNs) / 1_000_000;
            appendOut(String.format("[fire] Done @ %s  (fire=%d ms, total=%d ms)\n",
                    java.time.LocalTime.now(), fireMs, totalMs));
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

        /**
         * Extracts JSON code block from markdown-formatted text
         */
        private static String extractJson(String text) {
            // Look for ```json blocks
            int last = -1, start = -1, end = -1, idx = 0;
            while (true) {
                int s1 = indexOfIgnoreCase(text, "```json", idx);
                if (s1 < 0) break;
                int s2 = text.indexOf('\n', s1);
                int e  = text.indexOf("```", Math.max(s2, s1 + 7));
                if (e > 0) { last = s1; start = s2 + 1; end = e; }
                idx = s1 + 7;
            }
            if (last >= 0) return text.substring(start, end).trim();
            return null;
        }

        private static int indexOfIgnoreCase(String hay, String needle, int from) {
            final String h = hay.toLowerCase(Locale.ROOT);
            final String n = needle.toLowerCase(Locale.ROOT);
            return h.indexOf(n, from);
        }

        /**
         * Repairs common YAML issues where single-quoted strings are used with backslashes,
         * or where an extra trailing single quote appears. Converts to double-quoted JSON-style.
         */
        private static String fixYamlWeirdQuotes(String y) {
            String[] lines = y.split("\\r?\\n");
            StringBuilder out = new StringBuilder();
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("payload:")) {
                    int i = line.indexOf("payload:");
                    String before = line.substring(0, i + 8); // keep original indentation
                    String after = line.substring(i + 8).trim();
                    // Strip outer single quotes if present
                    if (after.startsWith("'") && after.length() >= 2) {
                        // Drop leading '
                        after = after.substring(1);
                        // If ends with two single quotes (YAML escape), drop one
                        if (after.endsWith("''")) after = after.substring(0, after.length() - 1);
                        // If ends with a single stray ', drop it
                        else if (after.endsWith("'")) after = after.substring(0, after.length() - 1);
                        // Unescape \' to ' and \\ to \
                        after = after.replace("\\'", "'").replace("\\\\", "\\");
                        // Re-escape for JSON double quotes
                        String jsonEscaped = after.replace("\\", "\\\\").replace("\"", "\\\"");
                        out.append(before).append(" \"").append(jsonEscaped).append("\"\n");
                        continue;
                    }
                }
                out.append(line).append("\n");
            }
            return out.toString();
        }

        private static boolean saneParamName(String s) {
            return s != null && s.matches("[A-Za-z0-9._-]{1,64}");
        }

        private static String chooseFallbackParam(HttpRequest base, String typeHint) {
            String hint = typeHint == null ? "" : typeHint.toUpperCase(Locale.ROOT);
            // Prefer params that exist in the hinted location
            List<? extends HttpParameter> params = base.parameters();
            if ("COOKIE".equals(hint)) {
                String cookie = base.headerValue("Cookie");
                if (cookie != null && !cookie.isBlank()) {
                    int eq = cookie.indexOf('=');
                    if (eq > 0) return cookie.substring(0, eq).trim();
                }
            }
            for (HttpParameter p : params) if (p.type() == HttpParameterType.URL)  return p.name();
            for (HttpParameter p : params) if (p.type() == HttpParameterType.BODY) return p.name();
            for (HttpParameter p : params) if (p.type() == HttpParameterType.JSON) return p.name();
            return "q";
        }

        // ========================= ENCODING UTILITIES =========================
        private static String encodeValue(String value, String kind) {
            if (value == null) return null;
            if (kind == null) return value;
            switch (kind) {
                case "URL":
                    return URLEncoder.encode(value, StandardCharsets.UTF_8);
                case "Base64":
                    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
                case "HTML":
                    return htmlEscape(value);
                default:
                    return value;
            }
        }

        private static String htmlEscape(String s) {
            if (s == null) return null;
            StringBuilder out = new StringBuilder(s.length() + 16);
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                switch (ch) {
                    case '&': out.append("&amp;"); break;
                    case '<': out.append("&lt;"); break;
                    case '>': out.append("&gt;"); break;
                    case '\"': out.append("&quot;"); break;
                    case '\'': out.append("&#x27;"); break;
                    default:
                        if (ch < 32 || ch > 126) {
                            out.append("&#x").append(Integer.toHexString(ch)).append(";");
                        } else {
                            out.append(ch);
                        }
                }
            }
            return out.toString();
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
        if (name == null || name.isBlank()) return cookieHeader; // Add validation
        Map<String,String> map = new LinkedHashMap<>();
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            for (String part : cookieHeader.split(";\\s*")) {
                int eq = part.indexOf('=');
                if (eq > 0) map.put(part.substring(0, eq), part.substring(eq + 1));
            }
        }
        map.put(name, value != null ? value : ""); // Handle null value
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
