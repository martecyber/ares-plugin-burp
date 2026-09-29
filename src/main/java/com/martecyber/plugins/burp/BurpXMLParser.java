package com.martecyber.plugins.burp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class BurpXMLParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern HOST_PORT_PATTERN = Pattern.compile("^(?:https?://)?([^/:]+)(?::(\\d+))?");

    @Override public String getToolId() { return "burp"; }
    @Override public String getDisplayName() { return "Burp Suite XML"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".xml"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains("<issues") && s.contains("<issue>");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new ByteArrayInputStream(content));

        Set<String> seenAssets = new HashSet<>();
        Map<String, String> current = null;
        String currentField = null;
        StringBuilder currentText = new StringBuilder();
        // Only meaningful for the <request>/<response> tags — Burp marks each one with its own
        // base64="true|false" attribute, so a request can be base64 while its response isn't (or
        // vice versa). Captured at START_ELEMENT (attributes aren't visible from CHARACTERS/
        // END_ELEMENT events in StAX) and consumed when the element closes.
        boolean currentBase64 = false;

        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                if ("issue".equals(tag)) {
                    current = new LinkedHashMap<>();
                    currentField = null;
                } else if (current != null) {
                    currentField = tag;
                    currentText.setLength(0);
                    if ("request".equals(tag) || "response".equals(tag)) {
                        currentBase64 = "true".equalsIgnoreCase(r.getAttributeValue(null, "base64"));
                    }
                }
            } else if (ev == XMLStreamConstants.CHARACTERS && currentField != null && current != null) {
                currentText.append(r.getText());
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                String tag = r.getLocalName();
                if ("issue".equals(tag) && current != null) {
                    processIssue(current, result, seenAssets);
                    current = null;
                    currentField = null;
                } else if (currentField != null && currentField.equals(tag) && current != null) {
                    String text = currentText.toString().trim();
                    if (("request".equals(tag) || "response".equals(tag)) && currentBase64) {
                        text = decodeBase64(text);
                    }
                    // Burp emits one <requestresponse> block per issue in the common case, but
                    // can attach several (one per proof-of-concept request) — the flat tag-keyed
                    // map only keeps the last one seen per issue, which is an acceptable
                    // simplification (DetectionHttpSample still lets an operator attach more
                    // samples manually afterwards).
                    current.put(currentField, text);
                    currentField = null;
                    currentText.setLength(0);
                }
            }
        }
        r.close();
        return result;
    }

    private void processIssue(Map<String, String> issue, ParseResult result, Set<String> seenAssets) {
        String host = issue.getOrDefault("host", "");
        String path = issue.getOrDefault("path", "");
        String name = issue.getOrDefault("name", "Unknown vulnerability");
        String severity = mapSeverity(issue.getOrDefault("severity", "Information"));
        String detail = issue.getOrDefault("issueDetail", "");
        String background = issue.getOrDefault("issueBackground", "");
        String remediationDetail = issue.getOrDefault("remediationDetail", "");
        String remediationBackground = issue.getOrDefault("remediationBackground", "");

        // Resolve host (WEB_APPLICATION) and the specific path (WEB_ENDPOINT) it was found on —
        // the issue is detected at the endpoint, but affects the whole web application.
        String webAppId = resolveHost(host, seenAssets, result);
        String endpointId = resolveEndpoint(webAppId, path, seenAssets, result);

        // Build description
        StringBuilder desc = new StringBuilder();
        if (!background.isBlank()) desc.append(background).append("\n\n");
        if (!detail.isBlank()) desc.append("Detail: ").append(detail).append("\n\n");
        if (!remediationBackground.isBlank()) desc.append("Remediation: ").append(remediationBackground).append("\n");
        if (!remediationDetail.isBlank()) desc.append(remediationDetail);

        // Every field the <issue> element carried (confidence, vulnerabilityClassifications,
        // references, ...), not the handful this parser's own title/description logic reads —
        // issue is already a generic tag→text capture (see the walker above), so dumping it as-is
        // is both complete and the simplest fix. request/response are excluded: they already get
        // their own DetectionHttpSample storage below, so keeping them out of raw_data avoids
        // silently duplicating a full HTTP transcript into the JSON viewer.
        String raw;
        try {
            Map<String, Object> rawMap = new LinkedHashMap<>(issue);
            rawMap.keySet().removeAll(List.of("request", "response"));
            raw = MAPPER.writeValueAsString(rawMap);
        } catch (Exception e) { raw = "{}"; }

        String templateId = "burp-" + name.toLowerCase().replaceAll("[^a-z0-9]+", "-");
        String fullTitle = name + (path != null && !path.isBlank() && !"/".equals(path) ? " [" + path + "]" : "");

        ParsedDetection pd = new ParsedDetection(fullTitle, severity, desc.toString().trim(), endpointId, templateId, raw);
        // detected_at is the endpoint (assetIdentifier above); affects the parent web application.
        // Null when the same as detectedAt (e.g. root-path issue) — ImportService then falls back
        // to the detection's own asset, matching every other importer's default behavior.
        if (webAppId != null && !webAppId.equals(endpointId)) pd.setAffectsIdentifier(webAppId);
        String request = issue.get("request");
        String response = issue.get("response");
        if ((request != null && !request.isBlank()) || (response != null && !response.isBlank())) {
            pd.setRequestContent(request);
            pd.setResponseContent(response);
        }
        result.addDetection(pd);
    }

    private String resolveHost(String host, Set<String> seenAssets, ParseResult result) {
        if (host == null || host.isBlank()) return null;
        Matcher m = HOST_PORT_PATTERN.matcher(host);
        if (!m.find()) return null;
        String hostname = m.group(1);
        String port = m.group(2);
        // Burp always scans web applications
        boolean isHttps = host.startsWith("https");
        String identifier = (isHttps ? "https://" : "http://") + hostname + (port != null ? ":" + port : "");
        if (!seenAssets.contains(identifier)) {
            seenAssets.add(identifier);
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("url", identifier);
            if (port != null) {
                meta.put("port", Integer.parseInt(port));
                meta.put("protocol", isHttps ? "HTTPS" : "HTTP");
            }
            result.addAsset(new ParsedAsset(identifier, AssetType.WEB_APPLICATION, meta));
        }
        return identifier;
    }

    /**
     * Resolves (and, on first sight, emits) the WEB_ENDPOINT asset for an issue's path, linked to
     * its parent WEB_APPLICATION — same identifier convention as KatanaParser/ensureWebEndpoints:
     * a blank/root path collapses to the webapp's own identifier string (still a distinct
     * WEB_ENDPOINT row, since asset dedup keys on identifier+type together).
     */
    private String resolveEndpoint(String webAppId, String path, Set<String> seenAssets, ParseResult result) {
        if (webAppId == null) return null;
        String cleanPath = path == null ? "" : path.trim();
        int q = cleanPath.indexOf('?');
        if (q >= 0) cleanPath = cleanPath.substring(0, q);
        int h = cleanPath.indexOf('#');
        if (h >= 0) cleanPath = cleanPath.substring(0, h);
        String endpointId = (cleanPath.isEmpty() || "/".equals(cleanPath)) ? webAppId : webAppId + cleanPath;
        if (seenAssets.add("endpoint:" + endpointId)) {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("path", cleanPath.isEmpty() ? "/" : cleanPath);
            result.addAsset(new ParsedAsset(endpointId, AssetType.WEB_ENDPOINT, meta));
            result.addLink(webAppId, endpointId, AssetLinkType.WEBAPP_ENDPOINT);
        }
        return endpointId;
    }

    /** Burp marks each <request>/<response> with base64="true|false"; decodes with the MIME
     *  decoder (tolerant of the line-wrapped blobs Burp's XML export produces) and falls back
     *  to the raw text if decoding fails for any reason. */
    private static String decodeBase64(String text) {
        if (text == null || text.isBlank()) return text;
        try {
            return new String(Base64.getMimeDecoder().decode(text), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return text;
        }
    }

    private String mapSeverity(String burpSeverity) {
        return switch (burpSeverity.toLowerCase()) {
            case "critical" -> "critical";
            case "high" -> "high";
            case "medium" -> "medium";
            case "low" -> "low";
            default -> "info";
        };
    }
}
