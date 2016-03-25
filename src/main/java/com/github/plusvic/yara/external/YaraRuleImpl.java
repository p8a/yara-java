package com.github.plusvic.yara.external;


import com.github.plusvic.yara.*;

import java.util.*;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraRuleImpl implements YaraRule {
    private String identifier;
    private List<String> tags = new ArrayList<>();
    private List<YaraMeta> metas = new ArrayList<>();
    private List<YaraString> strings = new ArrayList<>();

    public YaraRuleImpl(String identifier) {
        checkArgument(!Utils.isNullOrEmpty(identifier));

        this.identifier = identifier;
    }

    public void addTag(String tag) {
        this.tags.add(tag);
    }

    public void addMeta(YaraMeta meta) {
        this.metas.add(meta);
    }

    public void addString(YaraString string) {
        this.strings.add(string);
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Iterator<String> getTags() {
        return tags.iterator();
    }

    @Override
    public Iterator<YaraMeta> getMetadata() {
        return metas.iterator();
    }

    @Override
    public Iterator<YaraString> getStrings() {
        return strings.iterator();
    }
}
