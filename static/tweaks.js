(function () {
  const KEY = "cti.tweaks";
  const DEFAULTS = { aesthetic: "vapor", density: "normal", layout: "sitrep", accent: "" };
  const AESTHETICS = [["vapor","Vapor"],["terminal","Term"],["editorial","Edit"],["neutral","Neutral"]];
  const DENSITIES  = [["compact","Compact"],["normal","Normal"],["airy","Airy"]];
  const LAYOUTS    = [["sitrep","Sit-rep"],["queue","Queue"],["watchlist","Watch"]];
  const ACCENTS    = ["#ff3db4","#64f0ff","#c487ff","#00ff9c","#ffa44d"];

  function load() {
    try { return Object.assign({}, DEFAULTS, JSON.parse(localStorage.getItem(KEY) || "{}")); }
    catch (e) { return Object.assign({}, DEFAULTS); }
  }
  function save(state) { localStorage.setItem(KEY, JSON.stringify(state)); }

  function apply(state) {
    const b = document.body;
    if (state.aesthetic && state.aesthetic !== "vapor") b.setAttribute("data-aesthetic", state.aesthetic);
    else b.removeAttribute("data-aesthetic");
    b.setAttribute("data-density", state.density || "normal");
    b.setAttribute("data-layout", state.layout || "sitrep");
    if (state.accent) b.style.setProperty("--accent", state.accent);
    else b.style.removeProperty("--accent");
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") node.className = attrs[k];
      else if (k === "style") node.style.cssText = attrs[k];
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), attrs[k]);
      else node.setAttribute(k, attrs[k]);
    }
    if (children) children.forEach(c => node.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
    return node;
  }

  function seg(state, key, opts) {
    const wrap = el("div", { class: "seg" });
    opts.forEach(([v, label]) => {
      const b = el("button", {
        class: state[key] === v ? "on" : "",
        type: "button",
        onclick: () => { state[key] = v; save(state); apply(state); render(); },
      }, [label]);
      wrap.appendChild(b);
    });
    return wrap;
  }

  function field(label, inner) {
    return el("div", { class: "field" }, [el("span", { class: "label" }, [label]), inner]);
  }

  let panel, toggle, state;
  function render() {
    if (!panel) return;
    panel.replaceChildren(
      el("h3", null, ["Tweaks"]),
      field("Aesthetic", seg(state, "aesthetic", AESTHETICS)),
      field("Density",   seg(state, "density",   DENSITIES)),
      field("Layout",    seg(state, "layout",    LAYOUTS)),
      field("Accent", (function () {
        const wrap = el("div", { class: "swatches" });
        ACCENTS.forEach(color => {
          wrap.appendChild(el("span", {
            class: "swatch" + (state.accent === color ? " on" : ""),
            style: "background:" + color,
            onclick: () => { state.accent = state.accent === color ? "" : color; save(state); apply(state); render(); },
          }));
        });
        return wrap;
      })()),
    );
  }

  function init() {
    state = load();
    apply(state);

    toggle = el("button", {
      class: "tweaks-toggle",
      type: "button",
      title: "Tweaks",
      "aria-label": "Open tweaks panel",
      onclick: () => panel.classList.toggle("open"),
    }, ["◆"]);
    panel = el("div", { class: "tweaks" });

    document.body.appendChild(panel);
    document.body.appendChild(toggle);
    render();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
