package org.fordes.adg.rule.thread;

import cn.hutool.core.io.FileUtil;
import org.fordes.adg.rule.enums.RuleType;

import java.io.File;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

/**
 * 本地规则处理
 *
 * @author ChengFengsheng on 2022/7/7
 */
public class LocalRuleThread extends AbstractRuleThread {


    public LocalRuleThread(String ruleUrl, Map<RuleType, Set<File>> typeFileMap,
                           Set<String> filter, Map<File, Set<String>> fileDataMap) {
        super(ruleUrl, typeFileMap, filter, fileDataMap);
    }

    @Override
    InputStream getContentStream() {
        return FileUtil.getInputStream(getRuleUrl());
    }
}
