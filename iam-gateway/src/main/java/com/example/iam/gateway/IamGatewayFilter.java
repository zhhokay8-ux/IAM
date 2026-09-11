package com.example.iam.gateway;

import jakarta.servlet.Filter;
import org.springframework.core.Ordered;

public interface IamGatewayFilter extends Filter, Ordered {
}
