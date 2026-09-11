package com.example.iam.admin.web.config;

import java.util.List;

public record AdminConfigResponse(boolean readOnly, boolean restartRequired, List<AdminConfigSection> sections) {

    public record AdminConfigSection(String name, boolean dangerous, List<AdminConfigItem> items) {}

    public record AdminConfigItem(String key, String value, boolean redacted, boolean dangerous, boolean restartRequired) {}
}
