package com.example.iam.user.subject;

import com.example.iam.common.util.IdGenerator;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class UserSubjectGenerator {

    public UUID next() {
        return IdGenerator.uuidV7();
    }
}
