/* app.js — interactions de l'interface (vanilla JS, aucune dépendance) */
"use strict";

/* Exemples cliquables sur la page d'accueil */
document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    const input = document.getElementById("domain");
    if (!input) return;
    input.value = chip.dataset.domain || chip.textContent.trim();
    input.focus();
  });
});

/* Copier la fiche en texte (format repris dans un rapport) */
const copyBtn = document.getElementById("copy-report");
if (copyBtn) {
  copyBtn.addEventListener("click", async () => {
    const d = copyBtn.dataset;
    const report = [
      `Domain : ${d.domain}`,
      `Registrar : ${d.registrar || "—"}`,
      `Country : ${d.country || "—"}`,
      `IP : ${d.ip || "—"}`,
      `Domain age : ${d.age || "—"}`,
      `Risk : ${d.risk}`,
      `Analyse effectuée le : ${d.date}`,
    ].join("\n");
    try {
      await navigator.clipboard.writeText(report);
      copyBtn.textContent = "Copié ✓";
    } catch (err) {
      // Repli si le presse-papiers est bloqué (contexte non sécurisé)
      const area = document.createElement("textarea");
      area.value = report;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      copyBtn.textContent = "Copié ✓";
    }
    setTimeout(() => { copyBtn.textContent = "Copier la fiche"; }, 2000);
  });
}

/* Suppression d'une analyse depuis l'historique */
document.querySelectorAll(".delete-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const domain = btn.dataset.domain;
    if (!confirm(`Supprimer l'analyse de « ${domain} » ?`)) return;
    btn.disabled = true;
    try {
      const response = await fetch(`/api/analysis/${btn.dataset.id}`, { method: "DELETE" });
      const data = await response.json();
      if (data.ok) {
        const row = btn.closest("tr");
        if (row) row.remove();
      } else {
        alert("Suppression impossible : " + (data.error || "erreur inconnue"));
        btn.disabled = false;
      }
    } catch (err) {
      alert("Suppression impossible : " + err);
      btn.disabled = false;
    }
  });
});
