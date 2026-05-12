(function () {
  const LLMSec = {};

  LLMSec.renderTrendChart = function (canvasId, points) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const labels = points.map((p) => (p.timestamp || '').slice(0, 16).replace('T', ' '));
    const data = points.map((p) => p.score || 0);
    new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Vulnerability score',
          data,
          borderColor: '#2563eb',
          backgroundColor: 'rgba(37, 99, 235, 0.12)',
          tension: 0.25,
          fill: true,
          pointRadius: 3,
          pointBackgroundColor: '#2563eb',
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, max: 10, grid: { color: '#e2e8f0' } },
          x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true } },
        },
      },
    });
  };

  LLMSec.pollStatus = function (runId, onUpdate, intervalMs = 3000) {
    const tick = async () => {
      try {
        const resp = await fetch(`/api/runs/${runId}/status`);
        if (!resp.ok) {
          onUpdate('error');
          return;
        }
        const body = await resp.json();
        onUpdate(body.status, body);
        if (body.status === 'completed' || body.status === 'failed') return;
      } catch (err) {
        onUpdate('error');
        return;
      }
      setTimeout(tick, intervalMs);
    };
    tick();
  };

  LLMSec.wireTableFilter = function (inputId, tableId) {
    const input = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    if (!input || !table) return;
    input.addEventListener('input', () => {
      const q = input.value.toLowerCase();
      table.querySelectorAll('tbody tr').forEach((row) => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(q) ? '' : 'none';
      });
    });
  };

  LLMSec.wireRowLinks = function (tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;
    table.querySelectorAll('tr.row-clickable').forEach((row) => {
      row.addEventListener('click', () => {
        const href = row.getAttribute('data-href');
        if (href) window.location.href = href;
      });
    });
  };

  window.LLMSec = LLMSec;
})();
