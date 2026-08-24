package org.fordes.adg.rule.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author Chengfs on 2022/9/19
 */
@Getter
@AllArgsConstructor
public enum RuleType {

    /**
     * AdGuard Home 域名规则
     */
    DOMAIN("域名规则", true, null,
            new String[]{
                    "^(?:@@)?\\|\\|(?=[^\\s]*\\.)[A-Za-z0-9*]"
                            + "(?:[A-Za-z0-9_*.-]*[A-Za-z0-9*])?\\^(?:\\$important)?$"
            }, null),

    /**
     * Hosts规则
     */
    HOSTS("Hosts规则", true, null,
            new String[]{"^(?:(?:\\d{1,3}\\.){3}\\d{1,3}|[0-9A-Fa-f:]+)\\s+\\S+.*$"}, null),

    /**
     * /REGEX/ 格式的正则规则
     */
    REGEX("正则规则", true, null,
            new String[]{"^(?:@@)?/.+/(?:\\$important)?$"}, null),


    /**
     * 修饰规则，不被adGuardHome支持
     */
    MODIFY("修饰规则", false, null, null, null)
    ;


    /**
     * 描述
     */
    private final String desc;

    /**
     * 支持性，true则adGuardHome支持
     */
    private final boolean usually;

    /**
     * 识别标识，包含即通过
     */
    private final String[] identify;

    /**
     * 正向 正则，匹配一个即为通过
     */
    private final String[] match;

    /**
     * 排除 正则，全部不匹配即为通过
     */
    private final String[] exclude;
}
