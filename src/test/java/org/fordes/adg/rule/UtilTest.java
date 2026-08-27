package org.fordes.adg.rule;

import org.fordes.adg.rule.enums.OutputFormat;
import org.fordes.adg.rule.enums.RuleType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UtilTest {

    @Test
    void filtersCommentsAndMalformedRules() {
        assertEquals("||example.com^", Util.clearRule("||example.com^"));
        assertEquals("", Util.clearRule("! comment"));
        assertEquals("", Util.clearRule("# comment"));
        assertEquals("", Util.clearRule("### Donate: example.org"));
        assertEquals("", Util.clearRule("###AC_ad"));
        assertEquals("", Util.clearRule("||https://example.org"));
        assertEquals("#$?#html { remove: true; }", Util.clearRule("#$?#html { remove: true; }"));
    }

    @Test
    void recognizesIpv4AndIpv6HostsRules() {
        assertFalse(Util.validRule("example.com", RuleType.DOMAIN));
        assertTrue(Util.validRule("0.0.0.0 example.com", RuleType.HOSTS));
        assertTrue(Util.validRule("::1 localhost", RuleType.HOSTS));
        assertFalse(Util.validRule("999.999.999.999 example.com", RuleType.HOSTS));
        assertFalse(Util.validRule("0.0.0.0 invalid_domain", RuleType.HOSTS));
    }

    @Test
    void classifiesAdGuardHomeRulesByTheirActualSyntax() {
        assertTrue(Util.validRule("example.com##.advertisement", RuleType.MODIFY));
        assertEquals(RuleType.DOMAIN, Util.classifyRule("||example.org^"));
        assertEquals(RuleType.DOMAIN, Util.classifyRule("@@||example.org^"));
        assertEquals(RuleType.DOMAIN, Util.classifyRule("||cdn*.example.org^"));
        assertEquals(RuleType.MODIFY, Util.classifyRule("example.org"));
        assertEquals(RuleType.MODIFY, Util.classifyRule("*-stats.jpush.cn^"));
        assertEquals(RuleType.MODIFY, Util.classifyRule("*.91wan."));
        assertEquals(RuleType.MODIFY, Util.classifyRule("||booklng.com-*"));
        assertEquals(RuleType.MODIFY, Util.classifyRule("|load.ss."));
        assertEquals(RuleType.REGEX, Util.classifyRule("/^example\\.(org|com)$/"));
        assertEquals(RuleType.REGEX, Util.classifyRule("@@/^example\\.org$/$important"));
        assertEquals(RuleType.MODIFY, Util.classifyRule("example.com##.advertisement"));
        assertEquals(RuleType.MODIFY, Util.classifyRule("-attr.appsflyersdk.com^"));
    }

    @Test
    void writesHeadersForTheConfiguredOutputFormat() {
        String updatedAt = "2026-08-24 12:00:00";

        assertTrue(Util.buildHeader("all.txt", OutputFormat.ADGUARD, updatedAt)
                .startsWith("! Title:"));
        assertFalse(Util.buildHeader("all.txt", OutputFormat.ADGUARD, updatedAt)
                .contains("[Adblock Plus 2.0]"));
        assertTrue(Util.buildHeader("adgh.txt", OutputFormat.ADGUARD_HOME, updatedAt)
                .startsWith("! Title:"));
        assertTrue(Util.buildHeader("hosts.txt", OutputFormat.HOSTS, updatedAt)
                .startsWith("# Title:"));
    }

    @Test
    void ordersMergedRulesBySupportedSyntax() {
        assertEquals(List.of(
                        "! comment",
                        "# comment",
                        "@@||allowed.example.org/path.js$script",
                        "@@||allowed.example.org^",
                        "||example.org/ads.js$script,third-party",
                        "||example.org^",
                        "/^example\\.org$/",
                        "/ads\\d+/$script,domain=example.org",
                        "0.0.0.0 example.org",
                        "##.advertisement",
                        "/*/ad.js$script"
                ),
                Util.sortRules(List.of(
                        "/*/ad.js$script",
                        "##.advertisement",
                        "0.0.0.0 example.org",
                        "/^example\\.org$/",
                        "/ads\\d+/$script,domain=example.org",
                        "||example.org^",
                        "||example.org/ads.js$script,third-party",
                        "@@||allowed.example.org^",
                        "@@||allowed.example.org/path.js$script",
                        "# comment",
                        "! comment"
                )));
    }

    @Test
    void detectsCommonErrorPayloadsBeforeClassification() {
        assertTrue(Util.isSuspiciousPayloadLine("<!doctype html><html>"));
        assertTrue(Util.isSuspiciousPayloadLine("404: Not Found"));
        assertTrue(Util.isSuspiciousPayloadLine("upstream unavailable"));
        assertFalse(Util.isSuspiciousPayloadLine("||example.com^"));
    }
}
