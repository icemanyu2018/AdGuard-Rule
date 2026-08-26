package org.fordes.adg.rule;

import org.fordes.adg.rule.enums.RuleType;

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class GeneratedRulesValidator {

    private GeneratedRulesValidator() {
    }

    public static void validate(Map<File, Set<String>> outputs) {
        Map<String, Set<String>> rules = new HashMap<>();
        outputs.forEach((file, content) -> rules.put(file.getName(), content));

        Set<String> all = requireRules(rules, "all.txt");
        Set<String> adgh = requireRules(rules, "adgh.txt");
        Set<String> domain = requireRules(rules, "domain.txt");
        Set<String> hosts = requireRules(rules, "hosts.txt");
        Set<String> modify = requireRules(rules, "modify.txt");
        Set<String> regex = requireRules(rules, "regex.txt");

        validateBody("domain.txt", domain);
        validateBody("hosts.txt", hosts);
        validateBody("modify.txt", modify);
        validateBody("regex.txt", regex);
        validateType("domain.txt", domain, RuleType.DOMAIN);
        validateType("hosts.txt", hosts, RuleType.HOSTS);
        validateType("regex.txt", regex, RuleType.REGEX);

        if (all.stream().anyMatch(rule -> rule.startsWith("###"))
                || modify.stream().anyMatch(rule -> rule.startsWith("###"))) {
            throw new IllegalStateException("输出中包含不支持的通用 cosmetic 规则");
        }

        if (!all.equals(union(domain, regex, modify))) {
            throw new IllegalStateException("all.txt 与 DOMAIN、REGEX、MODIFY 合集不一致");
        }
        if (!adgh.equals(union(domain, regex, hosts))) {
            throw new IllegalStateException("adgh.txt 与 DOMAIN、REGEX、HOSTS 合集不一致");
        }
        if (!java.util.Collections.disjoint(all, hosts)) {
            throw new IllegalStateException("all.txt 不应包含 HOSTS 规则");
        }
    }

    private static Set<String> requireRules(Map<String, Set<String>> outputs, String name) {
        Set<String> rules = outputs.get(name);
        if (rules == null || rules.isEmpty()) {
            throw new IllegalStateException("缺少或为空的生成规则: " + name);
        }
        return rules;
    }

    private static void validateBody(String name, Set<String> rules) {
        for (String rule : rules) {
            if (rule == null || rule.isBlank()) {
                throw new IllegalStateException(name + " 包含空规则");
            }
            if (Util.isSuspiciousPayloadLine(rule)) {
                throw new IllegalStateException(name + " 包含疑似错误响应: " + rule);
            }
            String lower = rule.toLowerCase(java.util.Locale.ROOT);
            if (lower.startsWith("||http://") || lower.startsWith("||https://")) {
                throw new IllegalStateException(name + " 包含错误协议前缀: " + rule);
            }
            if ("[Adblock Plus 2.0]".equals(rule)) {
                throw new IllegalStateException(name + " 包含废弃订阅头");
            }
        }
    }

    private static void validateType(String name, Set<String> rules, RuleType type) {
        for (String rule : rules) {
            if (!Util.validRule(rule, type)) {
                throw new IllegalStateException(name + " 包含格式错误的规则: " + rule);
            }
        }
    }

    @SafeVarargs
    private static Set<String> union(Set<String>... groups) {
        Set<String> result = new HashSet<>();
        for (Set<String> group : groups) {
            result.addAll(group);
        }
        return result;
    }
}
