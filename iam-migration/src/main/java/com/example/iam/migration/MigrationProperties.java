package com.example.iam.migration;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "iam")
public class MigrationProperties {

    public static final Duration MIN_TICKET_TTL = Duration.ofSeconds(30);
    public static final Duration MAX_TICKET_TTL = Duration.ofSeconds(60);

    private boolean enabled = true;
    private final Migration migration = new Migration();
    private final Rollout rollout = new Rollout();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Migration getMigration() {
        return migration;
    }

    public Rollout getRollout() {
        return rollout;
    }

    public Duration ticketTtl() {
        return migration.ticketTtl();
    }

    public MigrationMode mode() {
        return migration.mode();
    }

    public boolean iamLoginEnabled() {
        return enabled && mode() != MigrationMode.LEGACY;
    }

    public boolean legacyLoginEnabled() {
        return !enabled || mode() != MigrationMode.IAM;
    }

    public void requireIamLoginEnabled() {
        if (!iamLoginEnabled()) {
            throw new com.example.iam.common.error.IamException(
                    com.example.iam.common.error.IamErrorCode.MIGRATION_DISABLED, "IAM login is disabled");
        }
    }

    public static class Migration {
        private String mode = MigrationMode.DUAL.name();
        private Duration ticketTtl = Duration.ofSeconds(45);

        public MigrationMode mode() {
            return MigrationMode.from(mode);
        }

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public Duration ticketTtl() {
            Duration ttl = ticketTtl == null ? Duration.ofSeconds(45) : ticketTtl;
            if (ttl.compareTo(MIN_TICKET_TTL) < 0) {
                return MIN_TICKET_TTL;
            }
            if (ttl.compareTo(MAX_TICKET_TTL) > 0) {
                return MAX_TICKET_TTL;
            }
            return ttl;
        }

        public Duration getTicketTtl() {
            return ticketTtl;
        }

        public void setTicketTtl(Duration ticketTtl) {
            this.ticketTtl = ticketTtl;
        }
    }

    public static class Rollout {
        private int percentage = 100;

        public int getPercentage() {
            return percentage;
        }

        public void setPercentage(int percentage) {
            this.percentage = percentage;
        }
    }
}
