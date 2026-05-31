document.querySelectorAll("button[data-endpoint]").forEach((button) => {
  button.addEventListener("click", () => run(button.dataset.endpoint, button.dataset.output, button));
});

document.querySelector("#run-all").addEventListener("click", async (event) => {
  await run("/analysis/run-all", "all-output", event.currentTarget);
});

async function run(endpoint, outputId, button) {
  const output = document.querySelector("#" + outputId);
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Running...";
  output.textContent = "Running analysis...";
  try {
    const response = await fetch(endpoint, { method: "POST" });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Request failed");
    }
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}
