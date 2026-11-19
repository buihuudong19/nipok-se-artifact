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
 * Control API of the customer-agent - called by k6 (outside) to run one end-to-end PSU journey.
 *
 * <p>The journey runs blocking (sequential java.net.http) -> moved to boundedElastic, the event loop is not blocked.
 */
@RestController
public class AgentController {

  private final AuthCodeJourney journey;

  public AgentController(AuthCodeJourney journey) {
    this.journey = journey;
  }

  /** Runs one Authorization Code journey. scope/customerId have defaults for quick tests. */
  @PostMapping("/agent/run")
  public Mono<Result> run(
      // LEAST PRIVILEGE by default: the journey only reads customer data => only 'customer:read' is requested.
      // granted = requested, consented and client-registered. Request more only when really needed (write/account).
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
