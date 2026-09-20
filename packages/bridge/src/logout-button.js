import { Modal, setIcon } from "obsidian";

// Obsidian has no sign-out of its own, so the button is placed next to its Help action:
// the drawer's vault actions in the mobile/tablet layout a browser gets, or the bottom of the
// left ribbon on desktop.
const BUTTON_CLASS = "ignis-logout-action";
const LABEL = "Sign out";

// Ordered by preference. Each entry mirrors the classes Obsidian's own icons carry there, so
// the button inherits their sizing and hover styling instead of needing CSS of its own.
const SLOTS = [
  // The mobile vault-switcher panel, where Obsidian keeps its own help and settings icons.
  {
    selector: ".workspace-drawer-vault-actions",
    tag: "span",
    cls: "clickable-icon",
    tooltip: "top",
  },
  // The drawer's bottom bar in the mobile/tablet layout a browser gets: vault switcher,
  // settings gear, pin.
  {
    selector: ".workspace-drawer-header",
    tag: "div",
    cls: "clickable-icon workspace-drawer-header-icon mod-raised",
    tooltip: "top",
  },
  // The bottom of the left ribbon in the desktop layout.
  {
    selector: ".side-dock-settings",
    tag: "div",
    cls: "clickable-icon side-dock-ribbon-action",
    tooltip: "right",
  },
];

class ConfirmLogoutModal extends Modal {
  onOpen() {
    this.titleEl.setText(LABEL);

    this.contentEl.createEl("p", {
      text: "This ends your Ignis session in this browser. Your vault stays on the server.",
    });

    const buttons = this.contentEl.createDiv("modal-button-container");

    const cancel = buttons.createEl("button", { text: "Cancel" });
    cancel.addEventListener("click", () => this.close());

    const confirm = buttons.createEl("button", { text: LABEL, cls: "mod-cta" });

    confirm.addEventListener("click", () => {
      confirm.disabled = true;
      window.__ignisAuth.signOut();
    });

    confirm.focus();
  }

  onClose() {
    this.contentEl.empty();
  }
}

function isVisible(el) {
  return !!(el.offsetParent || el.getClientRects().length);
}

// Both containers can exist at once - the ribbon is in the DOM but hidden in the mobile
// layout - so visibility, not existence, decides where the button goes.
function findSlot() {
  let fallback = null;

  for (const slot of SLOTS) {
    const container = document.querySelector(slot.selector);

    if (!container) {
      continue;
    }

    if (isVisible(container)) {
      return { ...slot, container };
    }

    fallback = fallback || { ...slot, container };
  }

  return fallback;
}

// The button belongs with Obsidian's own help and settings icons. Help wins when it is there,
// settings otherwise; both are matched on label and icon name, since neither is guaranteed
// across versions and layouts.
function findAnchor(container) {
  let settings = null;

  for (const child of container.children) {
    const label = (child.getAttribute("aria-label") || "").toLowerCase();
    const icon = child.querySelector("svg")?.getAttribute("class") || "";
    const cls = typeof child.className === "string" ? child.className : "";

    if (label.includes("help") || /help|question/i.test(icon)) {
      return { el: child, position: "afterend" };
    }

    if (
      !settings &&
      (label.includes("setting") ||
        cls.includes("mod-settings") ||
        /lucide-settings/.test(icon))
    ) {
      settings = { el: child, position: "beforebegin" };
    }
  }

  return settings;
}

function createButton(app, slot) {
  const el = document.createElement(slot.tag);

  el.className = `${slot.cls} ${BUTTON_CLASS}`;
  el.setAttribute("aria-label", LABEL);
  el.setAttribute("data-tooltip-position", slot.tooltip);
  setIcon(el, "log-out");

  el.addEventListener("click", () => new ConfirmLogoutModal(app).open());

  return el;
}

// Adds the sign-out button unless authentication is off. Obsidian builds the drawer lazily and
// rebuilds it on layout changes, so this keeps running rather than firing once at startup.
function initLogoutButton(plugin) {
  if (!window.__ignisAuth?.enabled) {
    return () => {};
  }

  const app = plugin.app;

  function ensure() {
    const slot = findSlot();

    if (!slot) {
      return;
    }

    const existing = document.querySelector(`.${BUTTON_CLASS}`);

    if (existing?.isConnected && existing.parentElement === slot.container) {
      return;
    }

    // Left over in a container that is gone or now hidden (a desktop/mobile layout switch).
    existing?.remove();

    const button = createButton(app, slot);
    const anchor = findAnchor(slot.container);

    if (anchor) {
      anchor.el.insertAdjacentElement(anchor.position, button);
    } else {
      slot.container.appendChild(button);
    }
  }

  // The drawer's action bar only exists once the drawer has been opened, and no workspace event
  // covers that, so the DOM itself is the signal. Debounced, and each pass is one querySelector.
  let pending = null;

  const observer = new MutationObserver(() => {
    if (pending !== null) {
      return;
    }

    pending = window.setTimeout(() => {
      pending = null;
      ensure();
    }, 200);
  });

  app.workspace.onLayoutReady(() => {
    ensure();
    observer.observe(document.body, { childList: true, subtree: true });
  });

  plugin.registerEvent(app.workspace.on("layout-change", ensure));
  plugin.registerEvent(app.workspace.on("resize", ensure));

  return () => {
    observer.disconnect();

    if (pending !== null) {
      window.clearTimeout(pending);
    }

    document.querySelector(`.${BUTTON_CLASS}`)?.remove();
  };
}

export { initLogoutButton };
