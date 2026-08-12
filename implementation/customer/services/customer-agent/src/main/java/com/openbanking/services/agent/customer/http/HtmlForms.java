package com.openbanking.services.agent.customer.http;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 * Scrape HTML form của Bank (login + consent) — thay vai browser parse trang.
 *
 * <p>Spring form login dùng field 'username'/'password'/'_csrf'. Trang consent (auto-generated
 * của Authorization Server) POST về authorize endpoint với hidden 'client_id'/'state' và các
 * checkbox name='scope'. Hàm dưới đọc generic (không phụ thuộc layout cứng) để bền với đổi version.
 */
public final class HtmlForms {

  private HtmlForms() {}

  /** Lấy giá trị input[name=_csrf] (rỗng nếu không có). */
  public static String extractCsrf(String html) {
    Document doc = Jsoup.parse(html);
    Element csrf = doc.selectFirst("input[name=_csrf]");
    return csrf != null ? csrf.attr("value") : "";
  }

  /** Lấy giá trị input[name=<name>] bất kỳ (vd 'nipokNonce' cho NIPoK). Rỗng nếu không có. */
  public static String extractHidden(String html, String name) {
    Element el = Jsoup.parse(html).selectFirst("input[name=" + name + "]");
    return el != null ? el.attr("value") : "";
  }

  /** Trang có phải form login? (có field password). */
  public static boolean isLoginPage(String html) {
    return Jsoup.parse(html).selectFirst("input[name=password]") != null;
  }

  /** Action của form login (vd /psu/auth khi loginProcessingUrl đổi). Mặc định /login. */
  public static String loginFormAction(String html) {
    Element form = Jsoup.parse(html).selectFirst("form:has(input[name=password])");
    String action = (form != null) ? form.attr("action") : "";
    return (action == null || action.isEmpty()) ? "/login" : action;
  }

  /** Trang có phải consent? (có checkbox/scope hoặc form trỏ authorize). */
  public static boolean isConsentPage(String html) {
    Document doc = Jsoup.parse(html);
    return doc.selectFirst("input[name=scope]") != null
        || doc.selectFirst("input[name=client_id]") != null;
  }

  /** Form consent đã parse: action + toàn bộ params (hidden + MỌI scope = approve all). */
  public record ConsentForm(String action, List<Map.Entry<String, String>> params) {}

  /**
   * Parse trang consent → approve TẤT CẢ scope (theo yêu cầu hardcode all-scope).
   * Gom hidden input (client_id, state, _csrf…) + mỗi checkbox scope thành 1 param scope.
   */
  public static ConsentForm parseConsent(String html) {
    Document doc = Jsoup.parse(html);
    Element form = doc.selectFirst("form:has(input[name=scope])");
    if (form == null) {
      form = doc.selectFirst("form:has(input[name=client_id])");
    }
    if (form == null) {
      form = doc.selectFirst("form");
    }
    if (form == null) {
      throw new IllegalStateException("Consent page không có <form>");
    }

    String action = form.attr("action");
    List<Map.Entry<String, String>> params = new ArrayList<>();

    // Hidden inputs (client_id, state, _csrf, ...)
    Elements hidden = form.select("input[type=hidden]");
    for (Element in : hidden) {
      String name = in.attr("name");
      if (!name.isEmpty()) {
        params.add(new SimpleEntry<>(name, in.attr("value")));
      }
    }
    // MỌI scope checkbox → approve all
    Elements scopes = form.select("input[name=scope]");
    for (Element s : scopes) {
      String v = s.attr("value");
      if (!v.isEmpty()) {
        params.add(new SimpleEntry<>("scope", v));
      }
    }
    return new ConsentForm(action, params);
  }
}
