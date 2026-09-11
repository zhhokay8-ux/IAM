package com.example.iam.migration;

import com.example.iam.session.IamSession;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;

public interface MigrationSsoCookieWriter {

    void write(HttpServletResponse response, IamSession session, Duration ttl);
}
