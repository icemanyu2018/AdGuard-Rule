package org.fordes.adg.rule;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GeneratedRulesValidatorTest {

    @Test
    void acceptsCompleteGeneratedOutputs() {
        assertDoesNotThrow(() -> GeneratedRulesValidator.validate(validOutputs()));
    }

    @Test
    void rejectsInvalidDomainRules() {
        Map<File, Set<String>> outputs = validOutputs();
        outputs.get(file("domain.txt")).add("example.org");

        assertThrows(IllegalStateException.class,
                () -> GeneratedRulesValidator.validate(outputs));
    }

    @Test
    void rejectsIncompleteAllRules() {
        Map<File, Set<String>> outputs = validOutputs();
        outputs.get(file("all.txt")).remove("##.advertisement");

        assertThrows(IllegalStateException.class,
                () -> GeneratedRulesValidator.validate(outputs));
    }

    @Test
    void rejectsMalformedProtocolRules() {
        Map<File, Set<String>> outputs = validOutputs();
        outputs.get(file("modify.txt")).add("||https://example.org");
        outputs.get(file("all.txt")).add("||https://example.org");

        assertThrows(IllegalStateException.class,
                () -> GeneratedRulesValidator.validate(outputs));
    }

    @Test
    void rejectsHostsRulesInAdghOutput() {
        Map<File, Set<String>> outputs = validOutputs();
        outputs.get(file("adgh.txt")).add("0.0.0.0 ads.example.org");

        assertThrows(IllegalStateException.class,
                () -> GeneratedRulesValidator.validate(outputs));
    }

    private static Map<File, Set<String>> validOutputs() {
        Set<String> domain = new HashSet<>(Set.of("@@||allowed.example.org^", "||example.org^"));
        Set<String> hosts = new HashSet<>(Set.of("0.0.0.0 ads.example.org"));
        Set<String> modify = new HashSet<>(Set.of("##.advertisement"));
        Set<String> regex = new HashSet<>(Set.of("/^ads\\d+\\.example\\.org$/"));

        Map<File, Set<String>> outputs = new HashMap<>();
        outputs.put(file("domain.txt"), domain);
        outputs.put(file("hosts.txt"), hosts);
        outputs.put(file("modify.txt"), modify);
        outputs.put(file("regex.txt"), regex);
        outputs.put(file("all.txt"), union(domain, regex, hosts, modify));
        outputs.put(file("adgh.txt"), union(domain, regex));
        return outputs;
    }

    @SafeVarargs
    private static Set<String> union(Set<String>... groups) {
        Set<String> result = new HashSet<>();
        for (Set<String> group : groups) {
            result.addAll(group);
        }
        return result;
    }

    private static File file(String name) {
        return new File("rule", name);
    }
}
