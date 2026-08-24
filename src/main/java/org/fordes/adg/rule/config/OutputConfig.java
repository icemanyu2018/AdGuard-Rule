package org.fordes.adg.rule.config;

import lombok.Data;
import org.fordes.adg.rule.enums.OutputFormat;
import org.fordes.adg.rule.enums.RuleType;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 输出配置
 *
 * @author Chengfs on 2022/9/19
 */
@Data
@Component
@ConfigurationProperties(prefix = "application.output")
public class OutputConfig {

    /**
     * 输出文件路径
     */
    private String path;

    /**
     * 输出文件列表
     */
    private Map<String, List<RuleType>> files = new LinkedHashMap<>();

    /**
     * 各输出文件的目标规则格式
     */
    private Map<String, OutputFormat> formats = new LinkedHashMap<>();
}
