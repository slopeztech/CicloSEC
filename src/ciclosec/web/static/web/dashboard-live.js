(() => {
  "use strict";

  const refreshInterval = 10_000;
  const feedback = document.getElementById("dashboard-live-feedback");
  const syncStatus = document.getElementById("dashboard-live-sync");
  const filterForm = document.querySelector(".filter-form");
  let activeRequest;
  let refreshFailed = false;
  let refreshDeferred = false;

  if (!document.getElementById("dashboard-live-content")) {
    return;
  }

  function announce(message, kind) {
    refreshFailed = false;
    if (!feedback) {
      return;
    }
    feedback.className = `notice notice--${kind}`;
    feedback.textContent = message;
    feedback.hidden = false;
  }

  function announceRefreshFailure() {
    announce("No se pudieron actualizar los datos. Se reintentará automáticamente.", "error");
    refreshFailed = true;
  }

  function clearRefreshFailure() {
    if (refreshFailed && feedback) {
      feedback.hidden = true;
    }
    refreshFailed = false;
  }

  function updateSyncStatus() {
    if (syncStatus) {
      const time = new Intl.DateTimeFormat(undefined, {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(new Date());
      syncStatus.textContent = `Última actualización automática: ${time}`;
    }
  }

  async function refreshDashboard(url, { pushState = false } = {}) {
    const requestUrl = new URL(url, window.location.href);
    if (requestUrl.origin !== window.location.origin) {
      return false;
    }

    activeRequest?.abort();
    const controller = new AbortController();
    activeRequest = controller;

    try {
      const response = await fetch(requestUrl, {
        cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "text/html",
          "X-CicloSec-Live": "dashboard",
        },
        signal: controller.signal,
      });
      if (response.redirected) {
        const finalUrl = new URL(response.url);
        if (
          finalUrl.origin === window.location.origin &&
          finalUrl.pathname === "/accounts/login/"
        ) {
          window.location.assign(finalUrl);
          return false;
        }
      }
      if (!response.ok) {
        throw new Error(`Dashboard refresh returned ${response.status}`);
      }

      const html = await response.text();
      const parsed = new DOMParser().parseFromString(html, "text/html");
      const nextContent = parsed.getElementById("dashboard-live-content");
      const currentContent = document.getElementById("dashboard-live-content");
      if (!nextContent || !currentContent) {
        throw new Error("Dashboard refresh response did not contain its content.");
      }
      const focusedInside = currentContent.contains(document.activeElement);
      if (focusedInside && !pushState) {
        refreshDeferred = true;
        if (syncStatus) {
          syncStatus.textContent = "Actualización pausada mientras interactúas con el panel.";
        }
        return false;
      }
      const headingId = focusedInside
        ? document.activeElement.closest("section[aria-labelledby]")?.getAttribute("aria-labelledby")
        : null;
      currentContent.replaceWith(nextContent);
      refreshDeferred = false;
      if (headingId) {
        const heading = document.getElementById(headingId);
        if (heading) {
          heading.setAttribute("tabindex", "-1");
          heading.focus({ preventScroll: true });
        }
      }
      if (pushState) {
        window.history.pushState({ dashboard: true }, "", requestUrl);
      }
      updateSyncStatus();
      clearRefreshFailure();
      return true;
    } catch (error) {
      if (error && typeof error === "object" && error.name === "AbortError") {
        return false;
      }
      console.error("No se pudo actualizar el dashboard.", error);
      announceRefreshFailure();
      return false;
    } finally {
      if (activeRequest === controller) {
        activeRequest = undefined;
      }
    }
  }

  function navigate(url) {
    void refreshDashboard(url, { pushState: true });
  }

  function updateFiltersFromLocation() {
    if (!filterForm) {
      return;
    }
    const params = new URLSearchParams(window.location.search);
    for (const name of ["asset_id", "affected_status"]) {
      const field = filterForm.elements.namedItem(name);
      if (field && "value" in field) {
        field.value = params.get(name) || "";
      }
    }
  }

  if (filterForm) {
    filterForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const url = new URL(filterForm.action, window.location.href);
      for (const [name, value] of new FormData(filterForm)) {
        if (typeof value === "string" && value.trim()) {
          url.searchParams.set(name, value);
        }
      }
      for (const name of ["assets_page", "scans_page", "findings_page"]) {
        url.searchParams.delete(name);
      }
      navigate(url);
    });
  }

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }
    const resetLink = event.target.closest("[data-live-reset]");
    if (resetLink && filterForm) {
      event.preventDefault();
      filterForm.reset();
      navigate(resetLink.href);
      return;
    }

    const link = event.target.closest("#dashboard-live-content .pagination a");
    if (
      !link ||
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return;
    }
    const url = new URL(link.href, window.location.href);
    if (url.origin === window.location.origin && url.pathname === window.location.pathname) {
      event.preventDefault();
      navigate(url);
    }
  });

  document.addEventListener("submit", async (event) => {
    if (
      !(event.target instanceof HTMLFormElement) ||
      !event.target.matches("[data-live-scan-form]")
    ) {
      return;
    }
    event.preventDefault();
    const form = event.target;
    const button = form.querySelector('button[type="submit"]');
    if (button) {
      button.disabled = true;
    }
    form.setAttribute("aria-busy", "true");

    try {
      const response = await fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "X-CicloSec-Live": "dashboard",
        },
      });
      if (response.redirected) {
        const finalUrl = new URL(response.url);
        if (
          finalUrl.origin === window.location.origin &&
          finalUrl.pathname === "/accounts/login/"
        ) {
          window.location.assign(finalUrl);
          return;
        }
      }
      const result = await response.json();
      if (typeof result.detail !== "string") {
        throw new Error("Scan request response is missing its message.");
      }
      announce(
        result.detail,
        response.ok ? "success" : "error",
      );
      if (response.status === 202 || result.scan_id) {
        await refreshDashboard(window.location.href);
      }
    } catch (error) {
      console.error("No se pudo solicitar el escaneo desde el dashboard.", error);
      announce(
        "No se pudo confirmar la solicitud. Consulta el historial antes de volver a intentarlo.",
        "error",
      );
    } finally {
      form.removeAttribute("aria-busy");
      if (button) {
        button.disabled = false;
      }
    }
  });

  window.addEventListener("popstate", () => {
    updateFiltersFromLocation();
    void refreshDashboard(window.location.href);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      void refreshDashboard(window.location.href);
    }
  });
  document.addEventListener("focusout", () => {
    window.setTimeout(() => {
      const content = document.getElementById("dashboard-live-content");
      if (
        refreshDeferred &&
        document.visibilityState === "visible" &&
        content &&
        !content.contains(document.activeElement)
      ) {
        void refreshDashboard(window.location.href);
      }
    }, 0);
  });

  window.setInterval(() => {
    if (document.visibilityState === "visible") {
      void refreshDashboard(window.location.href);
    }
  }, refreshInterval);
})();
