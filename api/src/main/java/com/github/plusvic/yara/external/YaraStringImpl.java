package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Utils;
import com.github.plusvic.yara.YaraMatch;
import com.github.plusvic.yara.YaraString;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static com.github.plusvic.yara.Preconditions.checkArgument;

public class YaraStringImpl implements YaraString {
    private String identifier;
    private List<YaraMatch> matches = new ArrayList<>();

    public YaraStringImpl(String identifier) {
        checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
    }

    public void addMatch(long offset, String value) {
        this.matches.add(new YaraMatchImpl(offset, value));
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Iterator<YaraMatch> getMatches() {
        return matches.iterator();
    }
}
