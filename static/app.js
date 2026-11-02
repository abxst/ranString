const $ = (id) => document.getElementById(id);
let catalog = [];

// Returns [{title, items}] either by catalog group or by complexity level.
function buildGroups(q, mode) {
  const match = (a) => !q || a.label.toLowerCase().includes(q) || a.id.includes(q);
  if (mode === "group") {
    return catalog.map((g) => ({ title: g.group, items: g.items.filter(match) }));
  }
  const byLevel = new Map();
  for (const g of catalog) {
    for (const a of g.items.filter(match)) {
      if (!byLevel.has(a.complexity)) byLevel.set(a.complexity, []);
      byLevel.get(a.complexity).push(a);
    }
  }
  const levels = [...byLevel.keys()].sort((x, y) => (mode === "asc" ? x - y : y - x));
  return levels.map((lv) => ({
    title: `Mức ${lv}/10`,
    items: byLevel.get(lv).sort((x, y) => x.label.localeCompare(y.label)),
  }));
}

function renderOptions() {
  const q = $("search").value.trim().toLowerCase();
  const mode = $("sort").value;
  const sel = $("algo");
  const prev = sel.value;
  sel.replaceChildren();
  for (const g of buildGroups(q, mode)) {
    if (!g.items.length) continue;
    const og = document.createElement("optgroup");
    og.label = g.title;
    for (const a of g.items) {
      const o = document.createElement("option");
      o.value = a.id;
      o.textContent = mode === "group" ? `${a.label}  · mức ${a.complexity}` : a.label;
      og.append(o);
    }
    sel.append(og);
  }
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  syncParams();
}

function findAlgo(id) {
  for (const g of catalog) for (const a of g.items) if (a.id === id) return a;
  return null;
}

function syncParam(box, label, input, p) {
  box.classList.toggle("d-none", !p);
  if (!p) return;
  label.textContent = `${p.label} (${p.min}–${p.max})`;
  input.min = p.min;
  input.max = p.max;
  input.value = p.default;
}

function syncParams() {
  const a = findAlgo($("algo").value);
  syncParam($("roundsBox"), $("roundsLabel"), $("rounds"), a && a.rounds);
  syncParam($("sizeBox"), $("sizeLabel"), $("size"), a && a.digest_size);
}

function resultRow(title, value) {
  const row = document.createElement("div");
  row.className = "mb-3";
  const head = document.createElement("div");
  head.className = "d-flex justify-content-between align-items-center mb-1";
  const t = document.createElement("small");
  t.className = "text-body-secondary";
  t.textContent = title;
  const copy = document.createElement("button");
  copy.className = "btn btn-sm btn-outline-secondary py-0";
  copy.textContent = "Copy";
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(value);
      copy.textContent = "Đã copy";
    } catch {
      copy.textContent = "Lỗi";
    }
    setTimeout(() => (copy.textContent = "Copy"), 1200);
  };
  head.append(t, copy);
  const pre = document.createElement("pre");
  pre.className = "result-pre bg-body-tertiary border rounded p-2 mb-0 font-monospace";
  pre.textContent = value;
  row.append(head, pre);
  return row;
}

function showError(msg) {
  const el = $("error");
  el.textContent = msg;
  el.classList.toggle("d-none", !msg);
}

async function generate() {
  const btn = $("go");
  showError("");
  const body = { algorithm: $("algo").value, length: $("length").value, text: $("text").value };
  if (!$("roundsBox").classList.contains("d-none")) body.rounds = $("rounds").value;
  if (!$("sizeBox").classList.contains("d-none")) body.digest_size = $("size").value;
  btn.disabled = true;
  btn.textContent = "Đang chạy...";
  try {
    const res = await fetch("/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Lỗi ${res.status}`);
    const rows = [resultRow("Input", data.input), resultRow(`Output (${data.elapsed_ms} ms)`, data.output)];
    for (const [k, v] of Object.entries(data.extra)) rows.push(resultRow(k, String(v)));
    $("resultBody").replaceChildren(...rows);
    $("result").classList.remove("d-none");
  } catch (e) {
    showError(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate";
  }
}

async function init() {
  try {
    catalog = await (await fetch("/api/algorithms")).json();
    renderOptions();
  } catch {
    showError("Không tải được danh sách thuật toán");
  }
}

$("search").addEventListener("input", renderOptions);
$("sort").addEventListener("change", renderOptions);
$("algo").addEventListener("change", syncParams);
$("go").addEventListener("click", generate);
init();
