const form = document.querySelector("#check-form");
const input = document.querySelector("#url-input");
const button = document.querySelector("#check-button");
const result = document.querySelector("#result");
const error = document.querySelector("#error-message");
const examples = ["https://secure-paypal.account-check.example/login", "https://www.wikipedia.org"];
let exampleIndex = 0;

document.querySelector("#example-button").addEventListener("click", () => {
  input.value = examples[exampleIndex++ % examples.length];
  input.focus();
});
document.querySelector("#clear-button").addEventListener("click", () => {
  result.hidden = true;
  input.value = "";
  error.hidden = true;
  input.focus();
});
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.hidden = true;
  button.disabled = true;
  button.querySelector("span:first-child").textContent = "Checking…";
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input.value }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not analyze that URL.");
    showResult(data);
  } catch (err) {
    error.textContent = err.message || "Could not reach the local analyzer. Is the server running?";
    error.hidden = false;
    result.hidden = true;
  } finally {
    button.disabled = false;
    button.querySelector("span:first-child").textContent = "Check link";
  }
});

function showResult(data) {
  const color = data.level === "high" ? "#d94b61" : data.level === "medium" ? "#ce8a20" : "#1e9e73";
  const ring = document.querySelector("#score-ring");
  ring.style.setProperty("--score", `${data.score}%`);
  ring.style.setProperty("--ring-color", color);
  document.querySelector("#score-number").textContent = data.score;
  document.querySelector("#risk-badge").textContent = data.label.toUpperCase();
  document.querySelector("#risk-badge").className = `risk-badge ${data.level}`;
  document.querySelector("#result-title").textContent = data.label;
  document.querySelector("#result-url").textContent = data.url;
  document.querySelector("#result-host").textContent = `Domain: ${data.host}`;
  document.querySelector("#disclaimer").textContent = data.disclaimer;
  const list = document.querySelector("#findings-list");
  list.replaceChildren();
  for (const finding of data.findings) {
    const item = document.createElement("li");
    item.className = "finding";
    const mark = document.createElement("span");
    mark.className = "finding-mark";
    mark.textContent = finding.points ? "!" : "✓";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = finding.title;
    const detail = document.createElement("p");
    detail.textContent = finding.detail;
    copy.append(title, detail);
    item.append(mark, copy);
    list.append(item);
  }
  result.hidden = false;
  result.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

