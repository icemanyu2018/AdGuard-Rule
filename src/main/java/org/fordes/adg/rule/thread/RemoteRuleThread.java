package org.fordes.adg.rule.thread;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import org.fordes.adg.rule.enums.RuleType;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class RemoteRuleThread extends AbstractRuleThread {


    public RemoteRuleThread(String ruleUrl, Map<RuleType, Set<File>> typeFileMap,
                            Set<String> filter, Map<File, Set<String>> fileDataMap) {
        super(ruleUrl, typeFileMap, filter, fileDataMap);
    }

    @Override
    InputStream getContentStream() {
        HttpResponse response = HttpRequest.get(getRuleUrl())
                .setFollowRedirects(true)
                .timeout(20000)
                .execute();
        if (!response.isOk()) {
            throw new IllegalStateException("规则源HTTP状态异常: " + getRuleUrl()
                    + " -> " + response.getStatus());
        }
        String contentType = response.header("Content-Type");
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("text/html")) {
            throw new IllegalStateException("规则源返回HTML内容: " + getRuleUrl());
        }
        String responseCharset = response.charset();
        if (responseCharset != null && !responseCharset.isBlank()) {
            setCharset(Charset.forName(responseCharset));
        }
        return response.bodyStream();
    }

}
