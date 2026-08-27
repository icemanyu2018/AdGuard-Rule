package org.fordes.adg.rule;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.ReUtil;
import cn.hutool.core.util.StrUtil;
import org.fordes.adg.rule.enums.OutputFormat;
import org.fordes.adg.rule.enums.RuleType;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Chengfs on 2022/9/19
 */
public class Util {

    /**
     * 将完整规则集排序后原子替换目标文件
     *
     * @param file    目标文件
     * @param content 内容集合
     */
    public static void writeAtomically(File file, Collection<String> content,
                                       OutputFormat format) throws IOException {
        FileUtil.mkParentDirs(file);
        Path target = file.toPath();
        Path temporary = Files.createTempFile(target.getParent(), file.getName() + ".", ".tmp");
        List<String> sorted = sortRules(content);

        try {
            try (BufferedWriter writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                writer.write(buildHeader(file.getName(), format,
                        DateTime.now().toString(DatePattern.NORM_DATETIME_PATTERN)));
                for (String rule : sorted) {
                    writer.write(rule);
                    writer.write(StrUtil.CRLF);
                }
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    public static List<String> sortRules(Collection<String> content) {
        List<String> bangComments = new ArrayList<>();
        List<String> hashComments = new ArrayList<>();
        List<String> exceptions = new ArrayList<>();
        List<String> blocks = new ArrayList<>();
        List<String> regex = new ArrayList<>();
        List<String> hosts = new ArrayList<>();
        List<String> other = new ArrayList<>();
        for (String rule : content) {
            if (rule.startsWith("!")) {
                bangComments.add(rule);
            } else if (isHashComment(rule)) {
                hashComments.add(rule);
            } else if (rule.startsWith("@@||")) {
                exceptions.add(rule);
            } else if (rule.startsWith("||")) {
                blocks.add(rule);
            } else if (isContentRegexRule(rule)) {
                regex.add(rule);
            } else if (validRule(rule, RuleType.HOSTS)) {
                hosts.add(rule);
            } else {
                other.add(rule);
            }
        }
        Collections.sort(bangComments);
        Collections.sort(hashComments);
        Collections.sort(exceptions);
        Collections.sort(blocks);
        Collections.sort(regex);
        Collections.sort(hosts);
        Collections.sort(other);
        bangComments.addAll(hashComments);
        bangComments.addAll(exceptions);
        bangComments.addAll(blocks);
        bangComments.addAll(regex);
        bangComments.addAll(hosts);
        bangComments.addAll(other);
        return bangComments;
    }

    private static boolean isContentRegexRule(String rule) {
        return ReUtil.isMatch("^(?:@@)?/.+/(?:\\$.*)?$", rule);
    }

    private static boolean isHashComment(String rule) {
        return rule.startsWith("#")
                && !rule.startsWith("##")
                && !rule.startsWith("#@")
                && !rule.startsWith("#$")
                && !rule.startsWith("#%")
                && !rule.startsWith("#?");
    }

    public static String buildHeader(String fileName, OutputFormat format, String updatedAt) {
        String marker = format == OutputFormat.HOSTS ? "#" : "!";
        return new StringBuilder(marker).append(" Title: AdGuard Rule - ").append(fileName).append(StrUtil.CRLF)
                .append(marker).append(" Last modified: ").append(updatedAt).append(StrUtil.CRLF)
                .append(marker).append(" Expires: 12 hours").append(StrUtil.CRLF)
                .append(marker).append(" Homepage: ").append(Constant.REPOSITORY).append(StrUtil.CRLF)
                .append(StrUtil.CRLF)
                .toString();
    }

    /**
     * 解析输出文件路径，不修改现有文件
     *
     * @param path 路径
     * @return {@link File}
     */
    public static File resolveFile(String path) {
        path = FileUtil.normalize(path);
        if (!FileUtil.isAbsolutePath(path)) {
            path = Constant.ROOT_PATH + File.separator + path;
        }
        return FileUtil.file(FileUtil.normalize(path));
    }

    /**
     * 校验内容是指定类型规则
     *
     * @param rule 内容
     * @param type    规则
     * @return 结果
     */
    public static boolean validRule(String rule, RuleType type) {

        if (type == RuleType.HOSTS) {
            return validHostsRule(rule);
        }

        //匹配标识，有标识时必须匹配
        if (ArrayUtil.isNotEmpty(type.getIdentify())) {
            if (!StrUtil.containsAny(rule, type.getIdentify())) {
                return false;
            }
        }

        if (ArrayUtil.isNotEmpty(type.getMatch()) || ArrayUtil.isNotEmpty(type.getExclude())) {
            //匹配正规则，需要至少满足一个
            if (ArrayUtil.isNotEmpty(type.getMatch())) {
                boolean match = false;
                for (String pattern : type.getMatch()) {
                    if (ReUtil.contains(pattern, rule)) {
                        match = true;
                        break;
                    }
                }
                if (!match) {
                    return false;
                }
            }

            //匹配负规则，需要全部不满足
            if (ArrayUtil.isNotEmpty(type.getExclude())) {
                for (String pattern : type.getExclude()) {
                    if (ReUtil.contains(pattern, rule)) {
                        return false;
                    }
                }
                return true;
            }

            return true;
        } else {
            return true;
        }

    }

    private static boolean validHostsRule(String rule) {
        return !parseHostsRule(rule).isEmpty();
    }

    private static List<String> parseHostsRule(String rule) {
        String content = rule.replaceFirst("\\s+#.*$", StrUtil.EMPTY);
        String[] fields = StrUtil.trim(content).split("\\s+");
        List<String> values = new ArrayList<>();
        for (String field : fields) {
            if (StrUtil.isNotBlank(field)) {
                values.add(field);
            }
        }
        if (values.size() < 2 || !validIpAddress(values.get(0))) {
            return Collections.emptyList();
        }
        for (int i = 1; i < values.size(); i++) {
            if (!ReUtil.isMatch("^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$", values.get(i))) {
                return Collections.emptyList();
            }
        }
        return values;
    }

    private static boolean validIpAddress(String value) {
        return parseIpAddress(value) != null;
    }

    private static InetAddress parseIpAddress(String value) {
        if (value.contains(":")) {
            try {
                InetAddress address = InetAddress.getByName(value);
                return address instanceof Inet6Address ? address : null;
            } catch (Exception ignored) {
                return null;
            }
        }
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) {
            return null;
        }
        byte[] address = new byte[4];
        for (int i = 0; i < octets.length; i++) {
            String octet = octets[i];
            if (!ReUtil.isMatch("^\\d{1,3}$", octet) || Integer.parseInt(octet) > 255) {
                return null;
            }
            address[i] = (byte) Integer.parseInt(octet);
        }
        try {
            return InetAddress.getByAddress(address);
        } catch (UnknownHostException ignored) {
            return null;
        }
    }

    /**
     * 清理 rule 字符串并过滤注释、订阅头和无效规则
     *
     * @param content 内容
     * @return 结果
     */
    public static String clearRule(String content) {
        content = StrUtil.isNotBlank(content) ? StrUtil.trim(content) : StrUtil.EMPTY;

        //有效性检测
        if (ReUtil.contains(Constant.EFFICIENT_REGEX, content)) {
            return StrUtil.EMPTY;
        }

        return content;
    }

    public static RuleType classifyRule(String rule) {
        if (validRule(rule, RuleType.DOMAIN)) {
            return RuleType.DOMAIN;
        }
        if (validRule(rule, RuleType.HOSTS)) {
            return RuleType.HOSTS;
        }
        if (validRule(rule, RuleType.REGEX)) {
            return RuleType.REGEX;
        }
        return validRule(rule, RuleType.MODIFY) ? RuleType.MODIFY : null;
    }

    public static boolean isSuspiciousPayloadLine(String line) {
        String value = StrUtil.trim(line).toLowerCase(Locale.ROOT);
        return value.startsWith("<!doctype html")
                || value.startsWith("<html")
                || value.startsWith("<head")
                || value.startsWith("<body")
                || value.equals("not found")
                || value.equals("404: not found")
                || value.equals("access denied")
                || value.equals("forbidden")
                || value.equals("bad gateway")
                || value.equals("service unavailable")
                || value.equals("upstream unavailable");
    }

    public static <K, T> void safePut(Map<K, Set<T>> map, K key, T val) {
        map.computeIfAbsent(key, ignored -> ConcurrentHashMap.newKeySet()).add(val);
    }

}
