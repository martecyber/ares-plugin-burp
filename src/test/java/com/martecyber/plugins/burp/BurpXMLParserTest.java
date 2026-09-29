package com.martecyber.plugins.burp;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers {@link BurpXMLParser}: WEB_APPLICATION/WEB_ENDPOINT resolution (http vs https, port
 * handling, query/fragment stripping), the per-issue base64 request/response decoding (each tag
 * carries its own independent {@code base64} attribute), severity mapping, and the
 * detected-at-endpoint / affects-web-application split that feeds DetectionHttpSample.
 */
class BurpXMLParserTest {

    private static String issuesXml(String... issues) {
        return "<issues burpVersion=\"2024.1\">" + String.join("", issues) + "</issues>";
    }

    @Test
    void validateRequiresIssuesAndIssueTags() {
        BurpXMLParser parser = new BurpXMLParser();
        assertTrue(parser.validate(issuesXml("<issue></issue>").getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<not-burp/>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void resolvesHttpsWebApplicationWithExplicitPort() throws Exception {
        String xml = issuesXml("""
            <issue>
              <serialNumber>1</serialNumber>
              <type>1234</type>
              <name>SQL injection</name>
              <host ip="1.2.3.4">https://example.com:8443</host>
              <path>/login</path>
              <severity>High</severity>
              <issueBackground>Background text.</issueBackground>
              <issueDetail>Detail text.</issueDetail>
            </issue>
            """);
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        ParsedAsset webapp = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.WEB_APPLICATION)).findFirst().orElseThrow();
        assertEquals("https://example.com:8443", webapp.getIdentifier());
        assertEquals(8443, webapp.getMetadata().get("port"));
        assertEquals("HTTPS", webapp.getMetadata().get("protocol"));

        ParsedAsset endpoint = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).findFirst().orElseThrow();
        assertEquals("https://example.com:8443/login", endpoint.getIdentifier());
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getLinkType().equals(AssetLinkType.WEBAPP_ENDPOINT)
            && l.getFromIdentifier().equals("https://example.com:8443")
            && l.getToIdentifier().equals("https://example.com:8443/login")));
    }

    @Test
    void detectionIsAttachedToTheEndpointAndAffectsTheParentWebApplication() throws Exception {
        String xml = issuesXml("""
            <issue>
              <name>SQL injection</name>
              <host>http://example.com</host>
              <path>/login</path>
              <severity>High</severity>
            </issue>
            """);
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("http://example.com/login", d.getAssetIdentifier());
        assertEquals("http://example.com", d.getAffectsIdentifier());
        assertEquals("SQL injection [/login]", d.getTitle());
    }

    @Test
    void rootPathIssueHasNoDistinctAffectsIdentifier() throws Exception {
        // Root/blank path collapses the endpoint identifier onto the webapp's own identifier —
        // affectsIdentifier is left null so ImportService falls back to the detection's own asset,
        // same default every other importer uses.
        String xml = issuesXml("""
            <issue>
              <name>Missing security header</name>
              <host>http://example.com</host>
              <path>/</path>
              <severity>Information</severity>
            </issue>
            """);
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("http://example.com", d.getAssetIdentifier());
        assertNull(d.getAffectsIdentifier());
        assertEquals("Missing security header", d.getTitle());
    }

    @Test
    void endpointPathStripsQueryStringAndFragment() throws Exception {
        String xml = issuesXml("""
            <issue>
              <name>Reflected XSS</name>
              <host>http://example.com</host>
              <path>/search?q=test&amp;page=2#top</path>
              <severity>Medium</severity>
            </issue>
            """);
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        ParsedAsset endpoint = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).findFirst().orElseThrow();
        assertEquals("http://example.com/search", endpoint.getIdentifier());
        assertEquals("/search", endpoint.getMetadata().get("path"));
    }

    @Test
    void decodesEachOfRequestAndResponseIndependentlyByItsOwnBase64Attribute() throws Exception {
        String rawRequest = "GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n";
        String encodedRequest = Base64.getEncoder().encodeToString(rawRequest.getBytes(StandardCharsets.UTF_8));
        String plainResponse = "HTTP/1.1 200 OK";

        String xml = issuesXml("""
            <issue>
              <name>Info leak</name>
              <host>http://example.com</host>
              <path>/login</path>
              <severity>Low</severity>
              <requestresponse>
                <request base64="true">%s</request>
                <response base64="false">%s</response>
              </requestresponse>
            </issue>
            """.formatted(encodedRequest, plainResponse));
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        ParsedDetection d = result.getDetections().get(0);
        assertEquals(rawRequest, d.getRequestContent());
        assertEquals(plainResponse, d.getResponseContent());
    }

    @Test
    void malformedBase64FallsBackToTheRawText() throws Exception {
        // A single leftover, non-padded character is what actually makes the MIME decoder throw
        // (it otherwise silently strips stray punctuation rather than rejecting it).
        String xml = issuesXml("""
            <issue>
              <name>Info leak</name>
              <host>http://example.com</host>
              <path>/login</path>
              <severity>Low</severity>
              <requestresponse>
                <request base64="true">A</request>
              </requestresponse>
            </issue>
            """);
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        assertEquals("A", result.getDetections().get(0).getRequestContent());
    }

    @Test
    void issueWithNeitherRequestNorResponseLeavesBothNull() throws Exception {
        String xml = issuesXml("""
            <issue>
              <name>Info leak</name>
              <host>http://example.com</host>
              <path>/login</path>
              <severity>Low</severity>
            </issue>
            """);
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        ParsedDetection d = result.getDetections().get(0);
        assertNull(d.getRequestContent());
        assertNull(d.getResponseContent());
    }

    @Test
    void severityIsMappedCaseInsensitivelyWithUnknownFallingBackToInfo() throws Exception {
        String xml = issuesXml(
            "<issue><name>A</name><host>http://a.com</host><path>/</path><severity>critical</severity></issue>",
            "<issue><name>B</name><host>http://a.com</host><path>/b</path><severity>HIGH</severity></issue>",
            "<issue><name>C</name><host>http://a.com</host><path>/c</path><severity>Medium</severity></issue>",
            "<issue><name>D</name><host>http://a.com</host><path>/d</path><severity>low</severity></issue>",
            "<issue><name>E</name><host>http://a.com</host><path>/e</path><severity>Information</severity></issue>",
            "<issue><name>F</name><host>http://a.com</host><path>/f</path><severity>Nonsense</severity></issue>"
        );
        List<ParsedDetection> detections = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8)).getDetections();

        assertEquals("critical", detections.get(0).getSeverity());
        assertEquals("high",     detections.get(1).getSeverity());
        assertEquals("medium",   detections.get(2).getSeverity());
        assertEquals("low",      detections.get(3).getSeverity());
        assertEquals("info",     detections.get(4).getSeverity());
        assertEquals("info",     detections.get(5).getSeverity());
    }

    @Test
    void descriptionJoinsBackgroundDetailAndRemediationSectionsWhenPresent() throws Exception {
        String xml = issuesXml("""
            <issue>
              <name>SQL injection</name>
              <host>http://example.com</host>
              <path>/login</path>
              <severity>High</severity>
              <issueBackground>Background text.</issueBackground>
              <issueDetail>Detail text.</issueDetail>
              <remediationBackground>Remediation background.</remediationBackground>
              <remediationDetail>Remediation detail.</remediationDetail>
            </issue>
            """);
        ParsedDetection d = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8)).getDetections().get(0);

        String desc = d.getDescription();
        assertTrue(desc.contains("Background text."));
        assertTrue(desc.contains("Detail: Detail text."));
        assertTrue(desc.contains("Remediation: Remediation background."));
        assertTrue(desc.contains("Remediation detail."));
    }

    @Test
    void hostAndPathAreDeduplicatedAcrossIssuesSharingTheSameEndpoint() throws Exception {
        String xml = issuesXml(
            "<issue><name>A</name><host>http://example.com</host><path>/login</path><severity>High</severity></issue>",
            "<issue><name>B</name><host>http://example.com</host><path>/login</path><severity>Low</severity></issue>"
        );
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_APPLICATION)).count());
        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.WEB_ENDPOINT)).count());
        assertEquals(2, result.getDetections().size());
    }

    @Test
    void issueWithoutAHostIsSkippedWithoutFailingTheWholeFile() throws Exception {
        String xml = issuesXml(
            "<issue><name>No host</name><path>/x</path><severity>Low</severity></issue>",
            "<issue><name>Has host</name><host>http://example.com</host><path>/y</path><severity>Low</severity></issue>"
        );
        ParseResult result = new BurpXMLParser().parse(xml.getBytes(StandardCharsets.UTF_8));

        assertEquals(2, result.getDetections().size());
        assertNull(result.getDetections().get(0).getAssetIdentifier());
        assertEquals("http://example.com/y", result.getDetections().get(1).getAssetIdentifier());
    }
}
