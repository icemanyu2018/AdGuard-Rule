package org.fordes.adg.rule;

import java.io.File;

public class Constant {

    public static final String ROOT_PATH = System.getProperty("user.dir");

    public static final String REPOSITORY = "https://github.com/hululu1068/AdGuard-Rule";

    public static final String LOCAL_RULE_SUFFIX = ROOT_PATH + File.separator + "rule";

    /**
     * 过滤注释、订阅头、不保留的通用 cosmetic 规则及无效协议前缀
     */
    public static final String EFFICIENT_REGEX = "^!|^\\[.*\\]$|^###|^#(?!(?:#|@|\\$|%|\\?))|^\\|\\|https?://";

}
