package com.openbanking.services.agent.customer.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.services.agent.customer.journey.AuthCodeJourney;
import com.openbanking.services.agent.customer.journey.AuthCodeJourney.Result;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * API điều khiển customer-agent — k6 (ngoài) gọi để chạy 1 journey PSU end-to-end.
 *
 * <p>Journey chạy blocking (java.net.http tuần tự) → đẩy sang boundedElastic, không chặn event-loop.
 */
@RestController
public class AgentController {

  private final AuthCodeJourney journey;

  public AgentController(AuthCodeJourney journey) {
    this.journey = journey;
  }

  /** Chạy 1 journey Authorization Code. scope/customerId có default để test nhanh. */
  @PostMapping("/agent/run")
  public Mono<Result> run(
      // G3.2 — LEAST-PRIVILEGE mặc định: journey chỉ đọc customer ⟹ chỉ xin 'customer:read'.
      // granted = requested ∩ consented ∩ client-registered. Xin thêm khi thật sự cần (write/account).
      @RequestParam(defaultValue = "customer:read") String scope,
      @RequestParam(defaultValue = "1") String customerId) {
    return Mono.fromCallable(() -> journey.run(scope, customerId))
        .subscribeOn(Schedulers.boundedElastic());
  }

  @GetMapping("/agent/health")
  public Mono<String> health() {
    return Mono.just("OK");
  }
}
