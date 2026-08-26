package org.fordes.adg.rule;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.date.TimeInterval;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.map.MapUtil;
import cn.hutool.core.thread.ExecutorBuilder;
import cn.hutool.core.util.StrUtil;
import cn.hutool.core.util.URLUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fordes.adg.rule.config.OutputConfig;
import org.fordes.adg.rule.config.RuleConfig;
import org.fordes.adg.rule.enums.OutputFormat;
import org.fordes.adg.rule.enums.RuleType;
import org.fordes.adg.rule.thread.AbstractRuleThread;
import org.fordes.adg.rule.thread.LocalRuleThread;
import org.fordes.adg.rule.thread.RemoteRuleThread;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@AllArgsConstructor
@SpringBootApplication
public class AdgRuleApplication implements ApplicationRunner {

    private final static int N = Runtime.getRuntime().availableProcessors();

    private final RuleConfig ruleConfig;

    private final OutputConfig outputConfig;

    private final ThreadPoolExecutor executor = ExecutorBuilder.create()
            .setCorePoolSize(2 * N)
            .setMaxPoolSize(2 * N)
            .setHandler(new ThreadPoolExecutor.CallerRunsPolicy())
            .build();


    @Override
    public void run(ApplicationArguments args) throws Exception {
        TimeInterval interval = DateUtil.timer();

        // 初始化输出映射，但在全部来源成功前不修改现有文件
        final Map<RuleType, Set<File>> typeFileMap = MapUtil.newHashMap();
        final Map<File, Set<String>> fileDataMap = new ConcurrentHashMap<>();
        final Map<File, OutputFormat> fileFormatMap = new ConcurrentHashMap<>();
        if (!outputConfig.getFiles().isEmpty()) {
            outputConfig.getFiles().forEach((fileName, types) -> {
                File file = Util.resolveFile(outputConfig.getPath() + File.separator + fileName);
                fileDataMap.putIfAbsent(file, ConcurrentHashMap.newKeySet());
                fileFormatMap.put(file, outputConfig.getFormats()
                        .getOrDefault(fileName, OutputFormat.ADGUARD_HOME));
                types.forEach(type -> Util.safePut(typeFileMap, type, file));
            });
        }

        //使用精确集合去重，避免布隆过滤器误判丢失规则
        Set<String> filter = ConcurrentHashMap.newKeySet();
        List<AbstractRuleThread> tasks = new ArrayList<>();

        //远程规则
        ruleConfig.getRemote().stream()
                .filter(StrUtil::isNotBlank)
                .map(URLUtil::normalize)
                .forEach(e -> {
                    RemoteRuleThread task = new RemoteRuleThread(e, typeFileMap, filter, fileDataMap);
                    tasks.add(task);
                    executor.execute(task);
                });
        //本地规则
        ruleConfig.getLocal().stream()
                .filter(StrUtil::isNotBlank)
                .map(e -> {
                    e = FileUtil.normalize(e);
                    if (FileUtil.isAbsolutePath(e)) {
                        return e;
                    }
                    return FileUtil.normalize(Constant.LOCAL_RULE_SUFFIX + File.separator + e);
                })
                .forEach(e -> {
                    LocalRuleThread task = new LocalRuleThread(e, typeFileMap, filter, fileDataMap);
                    tasks.add(task);
                    executor.execute(task);
                });

        if (tasks.isEmpty()) {
            throw new IllegalStateException("没有配置任何规则源");
        }

        executor.shutdown();
        if (!executor.awaitTermination(30, TimeUnit.MINUTES)) {
            executor.shutdownNow();
            throw new IllegalStateException("规则处理超时");
        }
        if (tasks.stream().anyMatch(task -> !task.isSuccessful())) {
            throw new IllegalStateException("至少一个规则源处理失败，阻止发布不完整结果");
        }
        GeneratedRulesValidator.validate(fileDataMap);
        for (Map.Entry<File, Set<String>> entry : fileDataMap.entrySet()) {
            Util.writeAtomically(entry.getKey(), entry.getValue(),
                    fileFormatMap.get(entry.getKey()));
        }
        log.info("Done! {} ms", interval.intervalMs());
    }

    public static void main(String[] args) {
        SpringApplication.run(AdgRuleApplication.class, args);
    }
}
