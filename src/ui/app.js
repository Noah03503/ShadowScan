/*
  ShadowScan — Logique du dashboard
  Author  : Noah Mordan
  License : MIT
*/

"use strict";

let rapportCourant = null;

// ─── Scan ─────────────────────────────────────────────────────────────────────

async function lancerScan() {
  const url      = document.getElementById("urlInput").value.trim();
  const scanBtn  = document.getElementById("scanBtn");
  const btnLabel = document.getElementById("btnLabel");

  if (!url) {
    secouer(document.getElementById("urlInput").parentElement);
    return;
  }

  const modules = Array.from(
    document.querySelectorAll(".mod-item input[type='checkbox']:checked")
  ).map(cb => cb.value);

  if (modules.length === 0) {
    secouer(document.querySelector(".modules-list"));
    return;
  }

  scanBtn.disabled   = true;
  btnLabel.textContent = "Analyse en cours...";
  masquerResultats();
  afficherProgression();
  animerProgression();

  try {
    const reponse = await fetch("/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, modules }),
    });

    if (!reponse.ok) {
      const err = await reponse.json();
      throw new Error(err.error || `Erreur HTTP ${reponse.status}`);
    }

    rapportCourant = await reponse.json();
    afficherResultats(rapportCourant);

  } catch (err) {
    afficherErreur(err.message);
  } finally {
    scanBtn.disabled     = false;
    btnLabel.textContent = "Lancer le scan";
    masquerProgression();
  }
}

document.getElementById("urlInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") lancerScan();
});

// ─── Progression ──────────────────────────────────────────────────────────────

function afficherProgression() {
  document.getElementById("progressSection").classList.remove("hidden");
  document.getElementById("progressFill").style.width = "0%";
  document.getElementById("progressPct").textContent  = "0%";
  document.getElementById("progressStep").textContent = "Initialisation...";
}

function masquerProgression() {
  document.getElementById("progressSection").classList.add("hidden");
}

function animerProgression() {
  const fill = document.getElementById("progressFill");
  const pct  = document.getElementById("progressPct");
  const step = document.getElementById("progressStep");

  const etapes = [
    { p: 8,  txt: "Connexion à la cible..." },
    { p: 20, txt: "Analyse des en-têtes HTTP..." },
    { p: 34, txt: "Injection des payloads XSS..." },
    { p: 48, txt: "Test d'injection SQL..." },
    { p: 60, txt: "Détection SSRF..." },
    { p: 70, txt: "Vérification des redirections..." },
    { p: 80, txt: "Analyse des fichiers exposés..." },
    { p: 88, txt: "Détection de traversée de répertoire..." },
    { p: 95, txt: "Génération du rapport..." },
  ];

  let i = 0;
  const interval = setInterval(() => {
    if (i >= etapes.length) { clearInterval(interval); return; }
    fill.style.width  = etapes[i].p + "%";
    pct.textContent   = etapes[i].p + "%";
    step.textContent  = etapes[i].txt;
    i++;
  }, 800);
}

// ─── Affichage des résultats ──────────────────────────────────────────────────

function afficherResultats(rapport) {
  const section = document.getElementById("resultats");
  section.classList.remove("hidden");

  // Score
  const score = rapport.score;
  const scoreEl = document.getElementById("scoreValue");
  scoreEl.textContent = score;

  if      (score >= 85) scoreEl.style.color = "var(--low)";
  else if (score >= 60) scoreEl.style.color = "var(--medium)";
  else if (score >= 35) scoreEl.style.color = "var(--high)";
  else                  scoreEl.style.color = "var(--critical)";

  const barFill = document.getElementById("scoreBarFill");
  barFill.style.width = score + "%";
  if      (score >= 85) barFill.style.background = "var(--low)";
  else if (score >= 60) barFill.style.background = "var(--medium)";
  else if (score >= 35) barFill.style.background = "var(--high)";
  else                  barFill.style.background = "var(--critical)";

  document.getElementById("scoreGrade").textContent = `GRADE : ${rapport.grade}`;

  // Résumé
  const grille = document.getElementById("summaryGrid");
  grille.innerHTML = "";
  const severites = [
    { key: "Critical", cls: "sev-critical", label: "Critique" },
    { key: "High",     cls: "sev-high",     label: "Élevé" },
    { key: "Medium",   cls: "sev-medium",   label: "Moyen" },
    { key: "Low",      cls: "sev-low",      label: "Faible" },
    { key: "Info",     cls: "sev-info",     label: "Info" },
  ];
  for (const s of severites) {
    const count = rapport.summary[s.key] ?? 0;
    const cell  = document.createElement("div");
    cell.className = `summary-cell ${s.cls}`;
    cell.innerHTML = `<span class="summary-count">${count}</span><span class="summary-label">${s.label}</span>`;
    grille.appendChild(cell);
  }

  // Méta
  document.getElementById("metaInfo").innerHTML =
    `Cible : ${echapper(rapport.meta.target)}<br />` +
    `Date  : ${new Date(rapport.meta.timestamp).toLocaleString("fr-FR")}<br />` +
    `Outil : ${rapport.meta.tool} ${rapport.meta.version}<br />` +
    `Auteur : ${rapport.meta.author}`;

  // Trouvailles
  const liste = document.getElementById("listeTrouvailles");
  liste.innerHTML = "";

  if (!rapport.findings || rapport.findings.length === 0) {
    liste.innerHTML = `<div style="padding:24px 20px;font-family:var(--font-mono);font-size:0.75rem;color:var(--text-3);">Aucune trouvaille à afficher.</div>`;
    return;
  }

  for (const f of rapport.findings) {
    liste.appendChild(construireCarte(f));
  }
}

function construireCarte(f) {
  const card = document.createElement("div");
  card.className = "trouvaille";

  const cls = classSeverite(f.severity);

  card.innerHTML = `
    <div class="trouvaille-header" onclick="basculerCarte(this)">
      <div class="sev-bar bg-${cls}"></div>
      <div class="trouvaille-info">
        <div class="trouvaille-titre">${echapper(f.title)}</div>
        <div class="trouvaille-module">${echapper(f.module)}</div>
      </div>
      <span class="sev-tag col-${cls}">${traductionSeverite(f.severity)}</span>
      <span class="chevron">▼</span>
    </div>
    <div class="trouvaille-body">
      <div class="trouvaille-contenu">
        <div class="champ">
          <span class="champ-label">Description</span>
          <p class="champ-texte">${echapper(f.description)}</p>
        </div>
        ${f.evidence ? `
        <div class="champ">
          <span class="champ-label">Preuve</span>
          <code class="champ-code">${echapper(f.evidence)}</code>
        </div>` : "<div></div>"}
        ${f.recommendation ? `
        <div class="champ plein-large">
          <span class="champ-label">Recommandation</span>
          <p class="champ-texte champ-reco reco-${cls}">${echapper(f.recommendation)}</p>
        </div>` : ""}
      </div>
    </div>
  `;

  return card;
}

function basculerCarte(header) {
  header.closest(".trouvaille").classList.toggle("ouvert");
}

// ─── Erreur ───────────────────────────────────────────────────────────────────

function afficherErreur(message) {
  const section = document.getElementById("resultats");
  section.classList.remove("hidden");

  document.getElementById("scoreValue").textContent  = "ERR";
  document.getElementById("scoreValue").style.color  = "var(--critical)";
  document.getElementById("scoreGrade").textContent  = "";
  document.getElementById("summaryGrid").innerHTML   = "";
  document.getElementById("metaInfo").innerHTML      = "";
  document.getElementById("scoreBarFill").style.width = "100%";
  document.getElementById("scoreBarFill").style.background = "var(--critical)";

  document.getElementById("listeTrouvailles").innerHTML = `
    <div class="trouvaille ouvert">
      <div class="trouvaille-header">
        <div class="sev-bar bg-critical"></div>
        <div class="trouvaille-info">
          <div class="trouvaille-titre">Échec du scan</div>
          <div class="trouvaille-module">Système</div>
        </div>
        <span class="sev-tag col-critical">Erreur</span>
      </div>
      <div class="trouvaille-body">
        <div class="trouvaille-contenu">
          <div class="champ plein-large">
            <span class="champ-label">Détails</span>
            <code class="champ-code">${echapper(message)}</code>
          </div>
          <div class="champ plein-large">
            <span class="champ-label">Recommandation</span>
            <p class="champ-texte champ-reco reco-critical">Vérifiez que l'URL cible est accessible et commence par http:// ou https://. Relancez le scan.</p>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ─── Export JSON ──────────────────────────────────────────────────────────────

function exporterJSON() {
  if (!rapportCourant) return;
  const blob = new Blob([JSON.stringify(rapportCourant, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const lien = document.createElement("a");
  const ts   = new Date().toISOString().slice(0, 19).replace(/:/g, "-");
  lien.href     = url;
  lien.download = `shadowscan-${ts}.json`;
  lien.click();
  URL.revokeObjectURL(url);
}

// ─── Export PDF ───────────────────────────────────────────────────────────────

function exporterPDF() {
  if (!rapportCourant) return;

  // Ouvrir toutes les cartes pour l'impression
  document.querySelectorAll(".trouvaille").forEach(t => t.classList.add("ouvert"));

  // Injecter un titre d'impression
  const titreImpression = document.createElement("div");
  titreImpression.id = "titre-impression";
  titreImpression.style.cssText = "display:none;";
  titreImpression.innerHTML = `
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:2px solid #dc2626;">
      <div style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#888;margin-bottom:8px;letter-spacing:0.1em;">RAPPORT D'ANALYSE DE SÉCURITÉ</div>
      <div style="font-family:'Bebas Neue',sans-serif;font-size:2.5rem;color:#111;line-height:1;">SHADOWSCAN</div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#888;margin-top:6px;">
        Cible : ${echapper(rapportCourant.meta.target)} &nbsp;|&nbsp;
        Date : ${new Date(rapportCourant.meta.timestamp).toLocaleString("fr-FR")} &nbsp;|&nbsp;
        Auteur : Noah Mordan
      </div>
    </div>
  `;

  const style = document.createElement("style");
  style.id = "style-impression";
  style.textContent = `
    @media print {
      #titre-impression { display: block !important; margin-bottom: 20px; }
      .hero { display: none !important; }
    }
  `;

  document.head.appendChild(style);
  document.querySelector(".main").prepend(titreImpression);

  window.print();

  // Nettoyage après impression
  setTimeout(() => {
    document.getElementById("titre-impression")?.remove();
    document.getElementById("style-impression")?.remove();
    document.querySelectorAll(".trouvaille").forEach(t => t.classList.remove("ouvert"));
  }, 1000);
}

// ─── Utilitaires ──────────────────────────────────────────────────────────────

function masquerResultats() {
  document.getElementById("resultats").classList.add("hidden");
  document.getElementById("listeTrouvailles").innerHTML = "";
  document.getElementById("summaryGrid").innerHTML      = "";
  document.getElementById("metaInfo").innerHTML         = "";
  document.getElementById("scoreValue").textContent     = "--";
  document.getElementById("scoreValue").style.color     = "";
  document.getElementById("scoreGrade").textContent     = "--";
  document.getElementById("scoreBarFill").style.width   = "0%";
}

function classSeverite(s) {
  return { Critical: "critical", High: "high", Medium: "medium", Low: "low", Info: "info" }[s] || "info";
}

function traductionSeverite(s) {
  return { Critical: "Critique", High: "Élevé", Medium: "Moyen", Low: "Faible", Info: "Info" }[s] || s;
}

function echapper(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function secouer(el) {
  el.style.animation = "none";
  el.offsetHeight;
  el.style.animation = "secouer 0.4s ease";
  setTimeout(() => el.style.animation = "", 400);
}
