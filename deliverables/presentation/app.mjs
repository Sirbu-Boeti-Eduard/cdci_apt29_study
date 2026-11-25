import { meta, slides } from "./deck.mjs";

const DECK_W = 1280;
const DECK_H = 720;

const root = document.getElementById("stage");
const progress = document.getElementById("progress");
const counter = document.getElementById("counter");
const notesPanel = document.getElementById("notes");
const notesBody = document.getElementById("notes-body");

let index = 0;
let notesOpen = false;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function header(slide) {
  const head = el("header", "slide-head");
  if (slide.kicker) {
    const kicker = el("div", "kicker");
    kicker.append(el("span", "kicker-mark"), el("span", "", slide.kicker));
    head.append(kicker);
  }
  head.append(el("h2", "slide-title", slide.title));
  if (slide.subtitle) head.append(el("p", "slide-subtitle", slide.subtitle));
  return head;
}

function footer(slide) {
  const foot = el("footer", "slide-foot");
  foot.append(el("span", "", "APT29 / SolarWinds"));
  return foot;
}

function bullets(slide) {
  const body = el("div", "body");
  if (slide.lead) body.append(el("p", "lead", slide.lead));
  const list = el("div", "grid-items");
  for (const item of slide.items) {
    const cell = el("div", "item");
    cell.append(el("h3", "", item.head), el("p", "", item.text));
    list.append(cell);
  }
  body.append(list);
  return body;
}

function stats(slide) {
  const body = el("div", "body");
  const row = el("div", "stats");
  for (const stat of slide.stats) {
    const cell = el("div", "stat");
    cell.append(el("div", "stat-value", stat.value), el("p", "stat-label", stat.label));
    row.append(cell);
  }
  body.append(row);
  if (slide.statement) body.append(el("p", "statement", slide.statement));
  return body;
}

function steps(slide) {
  const body = el("div", "body");
  const row = el("div", "steps");
  slide.steps.forEach((step, i) => {
    const cell = el("div", "step");
    cell.append(el("span", "step-num", String(i + 1).padStart(2, "0")));
    cell.append(el("h3", "", step.head), el("p", "", step.text));
    row.append(cell);
  });
  body.append(row);
  return body;
}

function table(slide) {
  const body = el("div", "body");
  const wrap = el("div", "table-wrap");
  const t = el("table", "data-table");
  const thead = el("thead");
  const hrow = el("tr");
  for (const h of slide.head) hrow.append(el("th", "", h));
  thead.append(hrow);
  t.append(thead);
  const tbody = el("tbody");
  for (const row of slide.rows) {
    const tr = el("tr");
    row.forEach((cell) => tr.append(el("td", "", cell)));
    tbody.append(tr);
  }
  t.append(tbody);
  wrap.append(t);
  body.append(wrap);
  if (slide.statement) body.append(el("p", "statement", slide.statement));
  return body;
}

function cards(slide) {
  const body = el("div", "body");
  const grid = el("div", "cards");
  grid.style.setProperty("--cols", slide.cards.length >= 4 ? "2" : "3");
  for (const card of slide.cards) {
    const cell = el("article", "card");
    cell.append(el("h3", "", card.head), el("p", "", card.text));
    grid.append(cell);
  }
  body.append(grid);
  return body;
}

function quote(slide) {
  const body = el("div", "body");
  const q = el("blockquote", "quote", slide.quote);
  body.append(q);
  if (slide.support) body.append(el("p", "support", slide.support));
  return body;
}

function checks(slide) {
  const body = el("div", "body");
  const list = el("div", "checks");
  for (const check of slide.checks) {
    const row = el("div", "check");
    row.append(el("span", "chip", "PASS"));
    const text = el("div");
    text.append(el("h3", "", check.label), el("p", "", check.detail));
    row.append(text);
    list.append(row);
  }
  body.append(list);
  if (slide.statement) body.append(el("p", "statement", slide.statement));
  return body;
}

function close(slide) {
  const body = el("div", "body close-body");
  for (const line of slide.lines) body.append(el("p", "close-line", line));
  return body;
}

const renderers = { bullets, stats, steps, table, cards, quote, checks, close };

function buildSlide(slide) {
  const section = el("section", `slide kind-${slide.kind}`);
  if (slide.kind !== "title") section.append(header(slide));
  if (slide.kind in renderers) section.append(renderers[slide.kind](slide));
  if (slide.kind === "title") {
    const body = el("div", "body title-body");
    body.append(el("h1", "", slide.title));
    if (slide.subtitle) body.append(el("p", "title-sub", slide.subtitle));
    const metaRow = el("div", "title-meta");
    for (const item of slide.meta) metaRow.append(el("span", "", item));
    body.append(metaRow);
    section.append(body);
  }
  if (slide.kind !== "title") section.append(footer(slide));
  return section;
}

for (const slide of slides) root.append(buildSlide(slide));

const nodes = [...root.querySelectorAll(".slide")];
counter.max = String(nodes.length);

function fit() {
  const pad = 48;
  const scale = Math.min(
    (window.innerWidth - pad) / DECK_W,
    (window.innerHeight - pad) / DECK_H,
  );
  document.documentElement.style.setProperty("--scale", String(scale));
}

function paint() {
  nodes.forEach((node, i) => node.classList.toggle("active", i === index));
  counter.textContent = `${String(index + 1).padStart(2, "0")} / ${String(nodes.length).padStart(2, "0")}`;
  progress.style.width = `${((index + 1) / nodes.length) * 100}%`;
  notesBody.textContent = slides[index].note ?? "";
  if (history.replaceState) history.replaceState(null, "", `#${index + 1}`);
}

function go(next) {
  index = Math.max(0, Math.min(nodes.length - 1, next));
  paint();
}

function toggleNotes() {
  notesOpen = !notesOpen;
  notesPanel.classList.toggle("open", notesOpen);
  document.body.classList.toggle("has-notes", notesOpen);
}

window.addEventListener("keydown", (event) => {
  if (event.key === "ArrowRight" || event.key === "PageDown" || event.key === " ") {
    event.preventDefault();
    go(index + 1);
  } else if (event.key === "ArrowLeft" || event.key === "PageUp") {
    event.preventDefault();
    go(index - 1);
  } else if (event.key === "Home") {
    go(0);
  } else if (event.key === "End") {
    go(nodes.length - 1);
  } else if (event.key === "n" || event.key === "N") {
    toggleNotes();
  } else if (event.key === "f" || event.key === "F") {
    if (document.fullscreenElement) document.exitFullscreen();
    else document.documentElement.requestFullscreen?.();
  }
});

document.getElementById("prev").addEventListener("click", () => go(index - 1));
document.getElementById("next").addEventListener("click", () => go(index + 1));

window.addEventListener("resize", fit);

const fromHash = Number.parseInt(location.hash.slice(1), 10);
index = Number.isFinite(fromHash) ? Math.min(nodes.length - 1, Math.max(0, fromHash - 1)) : 0;

fit();
paint();
