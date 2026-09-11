package com.example.iam.common.web;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.trace.TraceId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(IamException.class)
    public ResponseEntity<ApiErrorResponse> handleIamException(IamException ex) {
        IamErrorCode errorCode = ex.getErrorCode();
        String traceId = TraceId.currentOrNew();
        log.warn("IAM error traceId={} code={}", traceId, errorCode.getCode(), ex);
        return ResponseEntity.status(errorCode.getHttpStatus())
                .body(ApiErrorResponse.of(traceId, errorCode.getCode(), ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnhandled(Exception ex) {
        String traceId = TraceId.currentOrNew();
        log.error("Unhandled error traceId={}", traceId, ex);
        IamErrorCode errorCode = IamErrorCode.INTERNAL_ERROR;
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiErrorResponse.of(traceId, errorCode.getCode(), errorCode.getMessage()));
    }
}
