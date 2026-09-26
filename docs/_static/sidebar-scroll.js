// Keep the navigation sidebar where the reader left it. Every page is a full
// load, and Furo starts the sidebar at the top each time, so a click on an
// entry far down the list lands on a page whose own entry is out of view.
(() => {
  const KEY = "ntoseye:sidebar-scroll";

  const restore = () => {
    const sidebar = document.querySelector(".sidebar-scroll");
    if (!sidebar) return;

    const saved = sessionStorage.getItem(KEY);
    // Furo makes the sidebar scroll smoothly; restoring must not animate.
    if (saved !== null) sidebar.scrollTo({ top: Number(saved), behavior: "instant" });

    // Arriving from outside the sidebar (search, a link in a page, another
    // site), the saved position may not show this page: bring it into view.
    const current = sidebar.querySelector(".current-page > a");
    if (current) {
      const box = current.getBoundingClientRect();
      const view = sidebar.getBoundingClientRect();
      if (box.top < view.top || box.bottom > view.bottom) {
        current.scrollIntoView({ block: "center", behavior: "instant" });
      }
    }

    addEventListener("pagehide", () => {
      sessionStorage.setItem(KEY, String(sidebar.scrollTop));
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", restore);
  } else {
    restore();
  }
})();
