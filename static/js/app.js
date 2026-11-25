// Show/hide password buttons
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-toggle-password]");
  if (!btn) return;
  const input = document.getElementById(btn.dataset.togglePassword);
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  btn.textContent = show ? "Hide" : "Show";
});

// Ask before destructive actions (forms with data-confirm)
document.addEventListener("submit", (e) => {
  const message = e.target.dataset.confirm;
  if (message && !window.confirm(message)) e.preventDefault();
});

// Live password checklist on the registration page
const pw = document.getElementById("password");
const list = document.getElementById("pw-checklist");
if (pw && list) {
  const rules = {
    len: (v) => v.length >= 12, lower: (v) => /[a-z]/.test(v),
    upper: (v) => /[A-Z]/.test(v), digit: (v) => /\d/.test(v),
  };
  pw.addEventListener("input", () => {
    list.querySelectorAll("li").forEach((li) => li.classList.toggle("ok", rules[li.dataset.rule](pw.value)));
  });
}

// Character counter on the request form
const desc = document.getElementById("description");
const counter = document.getElementById("char-count");
if (desc && counter) {
  const update = () => { counter.textContent = `${desc.value.length} / ${desc.maxLength}`; };
  desc.addEventListener("input", update);
  update();
}
