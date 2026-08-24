package org.fordes.adg.rule.thread;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.date.TimeInterval;
import cn.hutool.core.exceptions.ExceptionUtil;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.io.LineHandler;
import cn.hutool.core.util.StrUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.Util;
import org.fordes.adg.rule.enums.RuleType;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 规则处理线程抽象
 *
 * @author ChengFengsheng on 2022/7/7
 */
@Slf4j
@Data
public abstract class AbstractRuleThread implements Runnable {

    private final String ruleUrl;

    private final Map<RuleType, Set<File>> typeFileMap;

    private final Set<String> filter;

    private final Map<File, Set<String>> fileDataMap;

    public AbstractRuleThread(String ruleUrl, Map<RuleType, Set<File>> typeFileMap,
                              Set<String> filter, Map<File, Set<String>> fileDataMap) {
        this.ruleUrl = ruleUrl;
        this.typeFileMap = typeFileMap;
        this.filter = filter;
        this.fileDataMap = fileDataMap;
    }

    private Charset charset = StandardCharsets.UTF_8;

    private volatile boolean successful = true;

    abstract InputStream getContentStream();

    @Override
    public void run() {
        TimeInterval interval = DateUtil.timer();
        AtomicInteger invalid = new AtomicInteger(0);
        AtomicInteger valid = new AtomicInteger(0);
        AtomicInteger added = new AtomicInteger(0);
        try {
            //按行读取并处理
            try (InputStream stream = getContentStream()) {
                IoUtil.readLines(stream, charset, (LineHandler) line -> {
                    if (StrUtil.isNotBlank(line)) {
                        String trimmed = StrUtil.trim(line);
                        if (Util.isSuspiciousPayloadLine(trimmed)) {
                            invalid.incrementAndGet();
                            log.debug("疑似错误响应，忽略: {}", line);
                            return;
                        }
                        String content = Util.clearRule(trimmed);
                        if (StrUtil.isNotBlank(content)) {
                            RuleType type = Util.classifyRule(content);
                            if (type == null) {
                                invalid.incrementAndGet();
                                log.debug("无效规则: {}", line);
                            } else {
                                valid.incrementAndGet();
                                if (filter.add(trimmed)) {
                                    added.incrementAndGet();
                                    typeFileMap.getOrDefault(type, Set.of())
                                            .forEach(item -> Util.safePut(fileDataMap, item, trimmed));
                                }
                            }
                        } else {
                            invalid.incrementAndGet();
                            log.debug("不是规则: {}", line);
                        }
                    }
                });
            }
            if (valid.get() == 0) {
                throw new IllegalStateException("规则源没有有效规则: " + ruleUrl);
            }
        } catch (Exception e) {
            successful = false;
            log.error(ExceptionUtil.stacktraceToString(e));
        } finally {
            log.info("规则<{}> 耗时 => {} ms 有效数 => {} 新增数 => {} 无效数 => {}",
                    ruleUrl, interval.intervalMs(), valid.get(), added.get(), invalid.get());
        }
    }

    public boolean isSuccessful() {
        return successful;
    }
}
