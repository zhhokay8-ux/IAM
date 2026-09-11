package com.example.iam.authorizationserver.oauth.token.exchange;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import org.springframework.stereotype.Component;

@Component
public class ActorTokenValidator {

    private final SubjectTokenValidator subjectTokenValidator;

    public ActorTokenValidator(SubjectTokenValidator subjectTokenValidator) {
        this.subjectTokenValidator = subjectTokenValidator;
    }

    public ActorContext validate(String token, String tokenType) {
        try {
            DelegationContext context = subjectTokenValidator.validate(token, tokenType);
            return new ActorContext(context.subject(), context.clientId());
        } catch (IamException ex) {
            if (ex.getErrorCode() == IamErrorCode.INVALID_ACTOR
                    || ex.getErrorCode() == IamErrorCode.ACTOR_UNAUTHORIZED) {
                throw ex;
            }
            throw new IamException(IamErrorCode.INVALID_ACTOR, ex.getMessage(), ex);
        }
    }
}
