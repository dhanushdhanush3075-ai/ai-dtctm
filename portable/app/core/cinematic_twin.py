"""
AI-DTCTM | Cinematic Digital Twin View (v27 — Pacman Journey Map)
═══════════════════════════════════════════════════════════════════════
Horizontal journey-map storybook:

  📄 SOURCE FILES  →  📁 CLONE FOLDER  →  ᗧ PACMAN VIRUS  →  ☂ SHIELD
       (stage 1)         (stage 2)            (stage 3)         (stage 4)

NARRATIVE
─────────────────
  1. IDLE         — files queued on the left, folder empty, pacman parked
  2. APPROACHING — small file icons slide along arrow into folder; folder fills
  3. ATTACKING   — pacman moves left toward the now-full folder, chomping
  4. INFECTED    — pacman overlaps folder, files inside flip red, glow danger
  5. MITIGATED   — umbrella-shield activates at stage 4, lightning hits pacman,
                    pacman gets X eyes and shrinks, files restore to navy

The current state is chosen from the attack log (logic unchanged from v26):
  no crits, no events           →  IDLE
  events present, no crits      →  APPROACHING
  some crits                    →  ATTACKING / INFECTED
  many crits + rate-limit clear →  MITIGATED (defence won)

NO Three.js — pure SVG + CSS animations. Pacman is the classic chomping
yellow circle (not cute). Shield is the umbrella + gear + key composite
the user picked from the icon library.
"""
from __future__ import annotations

import html as _html


def build_cinematic_view(
    recon: dict | None = None,
    attack_log: list | None = None,
    result: dict | None = None,
    title: str = "Cinematic Digital Twin",
    mitigation_log: list | None = None,
) -> str:
    """Render the SVG+CSS storybook scene.

    v34: mitigation_log was added so the cinematic responds to actual
    user-applied defenses, not just heuristic recon flags. When any
    mitigation run records a verify=ok event, the state jumps to
    'mitigated' regardless of attack-log crits — the user has actively
    proven the defense holds.
    """
    recon  = recon or {}
    log    = attack_log or []
    result = result or {}
    mit_log = mitigation_log or []

    crits = sum(1 for e in log if e.get("status") == "crit")
    oks   = sum(1 for e in log if e.get("status") == "ok")
    total = len(log)

    # v34 — mitigation evidence has highest priority
    mit_verified = any(
        (e.get("phase") == "verify" and e.get("status") == "ok")
        for e in mit_log
    )
    mit_applied = any(
        (e.get("phase") == "mitigate" and e.get("status") in ("ok", "info"))
        for e in mit_log
    )

    if total == 0:
        state = "idle"
        verdict_text = "Clone deployed · awaiting attack"
        verdict_color = "#60A5FA"
    elif mit_verified:
        # Defense was applied AND re-verify proved it held → mitigated
        state = "mitigated"
        verdict_text = f"🛡 Defense verified · {crits} hits blocked"
        verdict_color = "#16A34A"
    elif mit_applied:
        # Applied but not yet verified — still show shield approaching
        state = "mitigated"
        verdict_text = f"🛡 Defense applied · verifying…"
        verdict_color = "#0D9488"
    elif crits == 0:
        state = "approaching"
        verdict_text = f"Files loading · {total} probes"
        verdict_color = "#F59E0B"
    elif crits <= 2:
        state = "attacking"
        verdict_text = f"⚔ Pacman approaching · {crits} hits"
        verdict_color = "#F59E0B"
    elif crits <= 5:
        state = "infected"
        verdict_text = f"☣ Clone INFECTED · {crits} criticals"
        verdict_color = "#DC2626"
    else:
        state = "mitigated" if recon.get("rate_limit", {}).get("present") else "infected"
        if state == "mitigated":
            verdict_text = f"🛡 Shield held · pacman blocked"
            verdict_color = "#16A34A"
        else:
            verdict_text = f"☣ Clone COMPROMISED · {crits} criticals"
            verdict_color = "#DC2626"

    stack = result.get("stack") or {}
    clone_id = (result.get("clone_id") or "twin")[:18]
    lang  = stack.get("language", "?")
    fwk   = stack.get("framework", "?")
    risk  = int(recon.get("risk_score") or 0)

    title_safe   = _html.escape(title)
    verdict_safe = _html.escape(verdict_text)
    clone_safe   = _html.escape(clone_id)
    lang_safe    = _html.escape((lang + "/" + fwk).upper())

    return (_TEMPLATE
            .replace("__TITLE__",     title_safe)
            .replace("__STATE__",     state)
            .replace("__VERDICT__",   verdict_safe)
            .replace("__VERDICT_C__", verdict_color)
            .replace("__CLONE__",     clone_safe)
            .replace("__STACK__",     lang_safe)
            .replace("__CRITS__",     str(crits))
            .replace("__TOTAL__",     str(total))
            .replace("__RISK__",      str(risk)))


_TEMPLATE = r"""
<style>
  *,*::before,*::after { margin:0; padding:0; box-sizing:border-box; }
  html,body { background:transparent; overflow:hidden; }

  /* ── Stage ──────────────────────────────────────────────── */
  #stage {
    position: relative;
    width: 100%; height: 440px;
    background:
      radial-gradient(ellipse at 50% 35%,
        rgba(96,165,250,0.10) 0%, transparent 60%),
      linear-gradient(180deg, #0E1B2E 0%, #050B17 100%);
    border-radius: 14px;
    overflow: hidden;
    font-family: 'Inter', sans-serif;
    box-shadow:
      0 0 60px rgba(60,140,255,0.08),
      inset 0 0 80px rgba(0,0,0,0.5);
  }
  #stage::before {
    content: '';
    position: absolute; inset: 0;
    background-image:
      linear-gradient(rgba(96,165,250,0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(96,165,250,0.05) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
  }
  #stage::after {
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at center,
      transparent 55%, rgba(0,0,0,0.55) 100%);
    pointer-events: none;
  }

  /* ── Verdict bar ────────────────────────────────────────── */
  #verdict-bar {
    position: absolute; z-index: 8;
    top: 14px; left: 50%; transform: translateX(-50%);
    background: rgba(15,23,42,0.85);
    border: 1px solid var(--verdict-c, #60A5FA);
    border-radius: 999px;
    padding: 7px 18px;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 11px; font-weight: 700;
    color: #F8FAFC;
    letter-spacing: 0.08em;
    backdrop-filter: blur(8px);
    box-shadow: 0 0 22px var(--verdict-c, #60A5FA);
    text-shadow: 0 0 10px var(--verdict-c, #60A5FA);
  }

  /* ── Corner HUD cards ───────────────────────────────────── */
  .corner {
    position: absolute; z-index: 8;
    background: rgba(15,23,42,0.85);
    border: 1px solid rgba(96,165,250,0.3);
    border-radius: 8px;
    padding: 8px 12px;
    font-family: 'JetBrains Mono', monospace;
    color: #BFDBFE;
    font-size: 10px;
    backdrop-filter: blur(6px);
    pointer-events: none;
  }
  .corner .lbl {
    font-size: 8px; letter-spacing: 0.18em; opacity: 0.65;
    text-transform: uppercase; color: #93C5FD;
  }
  .corner .val {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 17px; font-weight: 800;
    color: #FFFFFF;
    margin-top: 2px; line-height: 1;
  }
  #c-clone { top: 14px;  left:  14px; }
  #c-stack { top: 14px;  right: 14px; }
  #c-risk  { bottom: 14px; left:  14px; }
  #c-stats { bottom: 14px; right: 14px; }

  /* ── Stage labels under journey ─────────────────────────── */
  .stage-label {
    position: absolute; z-index: 6;
    top: 360px;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 11px; font-weight: 700;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: #64748B;
    text-align: center;
    width: 200px;
    transition: color 0.6s, text-shadow 0.6s;
  }
  .stage-label .sub {
    display: block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px; font-weight: 500;
    letter-spacing: 0.08em;
    color: #475569;
    margin-top: 3px;
    text-transform: none;
  }
  #lbl-files  { left:   40px; }
  #lbl-folder { left:  320px; }
  #lbl-virus  { left:  620px; }
  #lbl-shield { left:  920px; }

  /* Highlight active stage label */
  .state-idle       #lbl-files,
  .state-approaching #lbl-files,
  .state-approaching #lbl-folder,
  .state-attacking   #lbl-virus,
  .state-attacking   #lbl-folder,
  .state-infected    #lbl-virus,
  .state-infected    #lbl-folder,
  .state-mitigated   #lbl-shield,
  .state-mitigated   #lbl-folder {
    color: #F8FAFC;
    text-shadow: 0 0 12px rgba(96,165,250,0.6);
  }
  .state-infected #lbl-virus   { color: #FCA5A5; text-shadow: 0 0 14px #DC2626; }
  .state-infected #lbl-folder  { color: #FCA5A5; text-shadow: 0 0 14px #DC2626; }
  .state-mitigated #lbl-shield { color: #BBF7D0; text-shadow: 0 0 14px #16A34A; }

  /* ── SVG canvas ─────────────────────────────────────────── */
  svg.journey {
    position: absolute; inset: 0;
    width: 100%; height: 100%;
    z-index: 4;
  }

  /* ── Station ring (the big circle around each icon) ─────── */
  .station-ring {
    fill: rgba(15,23,42,0.6);
    stroke: rgba(96,165,250,0.35);
    stroke-width: 2;
    transition: stroke 0.6s, stroke-width 0.6s;
  }
  .state-idle .ring-1,
  .state-approaching .ring-1,
  .state-approaching .ring-2 {
    stroke: #60A5FA; stroke-width: 3;
    filter: drop-shadow(0 0 16px #60A5FA);
  }
  .state-attacking .ring-2,
  .state-attacking .ring-3 {
    stroke: #F59E0B; stroke-width: 3;
    filter: drop-shadow(0 0 16px #F59E0B);
  }
  .state-infected .ring-2,
  .state-infected .ring-3 {
    stroke: #DC2626; stroke-width: 4;
    filter: drop-shadow(0 0 22px #DC2626);
    animation: ringPulse 1.1s ease-in-out infinite;
  }
  .state-mitigated .ring-4 {
    stroke: #22C55E; stroke-width: 4;
    filter: drop-shadow(0 0 22px #22C55E);
  }
  @keyframes ringPulse {
    0%,100% { stroke-width: 4; }
    50%     { stroke-width: 6; }
  }

  /* ── Connector arrows between stations ──────────────────── */
  .arrow-path {
    fill: none;
    stroke: rgba(96,165,250,0.25);
    stroke-width: 2.5;
    stroke-dasharray: 8 6;
    transition: stroke 0.6s;
  }
  .arrow-head {
    fill: rgba(96,165,250,0.4);
    transition: fill 0.6s;
  }
  /* Active arrow lights up + animates dashes */
  .state-approaching .arr-1 { stroke: #60A5FA; animation: dashMarch 1.4s linear infinite; }
  .state-approaching .arr-1-head { fill: #60A5FA; }
  .state-attacking   .arr-2 { stroke: #F59E0B; animation: dashMarch 1.0s linear infinite; }
  .state-attacking   .arr-2-head { fill: #F59E0B; }
  .state-infected    .arr-2 { stroke: #DC2626; animation: dashMarch 0.8s linear infinite; }
  .state-infected    .arr-2-head { fill: #DC2626; }
  .state-mitigated   .arr-3 { stroke: #22C55E; animation: dashMarch 1.1s linear infinite reverse; }
  .state-mitigated   .arr-3-head { fill: #22C55E; }
  @keyframes dashMarch {
    to { stroke-dashoffset: -28; }
  }

  /* ── Flying source-file particles on arrow 1 ────────────── */
  .flying-file { opacity: 0; }
  .state-approaching .flying-file {
    animation: flyToFolder 2.4s ease-in-out infinite;
  }
  .state-approaching .flying-file.delay-1 { animation-delay: 0.6s; }
  .state-approaching .flying-file.delay-2 { animation-delay: 1.2s; }
  .state-approaching .flying-file.delay-3 { animation-delay: 1.8s; }
  @keyframes flyToFolder {
    0%   { opacity: 0; transform: translate(0,0)     scale(0.5); }
    15%  { opacity: 1; }
    80%  { opacity: 1; transform: translate(220px,0) scale(0.7); }
    100% { opacity: 0; transform: translate(260px,0) scale(0.3); }
  }

  /* ── Folder file count fills as state advances ──────────── */
  .folder-file { opacity: 0; transition: opacity 0.6s; }
  .state-approaching .folder-file.ff-1 { opacity: 1; }
  .state-approaching .folder-file.ff-2 { opacity: 0.5; }
  .state-attacking   .folder-file,
  .state-infected    .folder-file,
  .state-mitigated   .folder-file { opacity: 1; }
  .state-infected    .folder-file { fill: #DC2626; }
  .state-mitigated   .folder-file { fill: #22C55E; }

  /* ── Folder body colour responds to state ───────────────── */
  .folder-body { fill: #1E3A8A; stroke: #3B82F6; transition: fill 0.6s, stroke 0.6s; }
  .folder-tab  { fill: #1E40AF; stroke: #3B82F6; transition: fill 0.6s, stroke 0.6s; }
  .state-infected .folder-body { fill: #7F1D1D; stroke: #DC2626;
    animation: folderShake 0.18s ease-in-out infinite; }
  .state-infected .folder-tab  { fill: #991B1B; stroke: #DC2626; }
  .state-mitigated .folder-body { fill: #14532D; stroke: #22C55E; }
  .state-mitigated .folder-tab  { fill: #166534; stroke: #22C55E; }
  @keyframes folderShake {
    0%,100% { transform: translate(0,0); }
    25%     { transform: translate(-2px,1px); }
    75%     { transform: translate(2px,-1px); }
  }

  /* ── PACMAN — chomping mouth + dash to folder ───────────── */
  .pacman-group { transform-origin: 720px 190px; }
  /* Chomping animation: two halves rotate */
  .pacman-top    { transform-origin: 720px 190px;
                    animation: chompTop 0.45s ease-in-out infinite; }
  .pacman-bottom { transform-origin: 720px 190px;
                    animation: chompBottom 0.45s ease-in-out infinite; }
  @keyframes chompTop {
    0%,100% { transform: rotate(-40deg); }
    50%     { transform: rotate(0deg);    }
  }
  @keyframes chompBottom {
    0%,100% { transform: rotate(40deg); }
    50%     { transform: rotate(0deg);   }
  }
  /* Pacman starts parked, dashes left to folder on attack */
  .state-idle        .pacman-group,
  .state-approaching .pacman-group { transform: translate(0,0); }
  .state-attacking   .pacman-group { animation: pacmanCharge 1.6s ease-in-out infinite; }
  .state-infected    .pacman-group { transform: translate(-260px,0); }
  .state-mitigated   .pacman-group { transform: translate(0,30px);
                                       opacity: 0.4;
                                       animation: pacmanDie 1.8s ease-out forwards; }
  @keyframes pacmanCharge {
    0%   { transform: translate(0,0); }
    50%  { transform: translate(-140px,0); }
    100% { transform: translate(0,0); }
  }
  @keyframes pacmanDie {
    0%   { transform: translate(0,0)   scale(1)   rotate(0); opacity: 1; }
    40%  { transform: translate(20px,40px) scale(0.6) rotate(120deg); opacity: 0.5; }
    100% { transform: translate(60px,120px) scale(0.2) rotate(360deg); opacity: 0; }
  }

  /* Pacman eye + X-eye for death */
  .pac-eye           { fill: #0F172A; opacity: 1; transition: opacity 0.4s; }
  .pac-eye-x         { stroke: #0F172A; stroke-width: 4; stroke-linecap: round; opacity: 0; }
  .state-mitigated .pac-eye   { opacity: 0; }
  .state-mitigated .pac-eye-x { opacity: 1; }

  /* Stop chomping on mitigated */
  .state-mitigated .pacman-top,
  .state-mitigated .pacman-bottom { animation: none; }

  /* ── Shield (umbrella + gear + key) responds to state ──── */
  .shield-group { opacity: 0.35; transform-origin: 1020px 190px;
                   transition: opacity 0.6s, transform 0.6s; }
  .state-mitigated .shield-group {
    opacity: 1;
    animation: shieldActivate 1.6s ease-out forwards;
  }
  @keyframes shieldActivate {
    0%   { transform: scale(1); }
    30%  { transform: scale(1.18); filter: drop-shadow(0 0 24px #22C55E); }
    100% { transform: scale(1.08); filter: drop-shadow(0 0 18px #22C55E); }
  }

  /* Lightning bolt from shield on mitigation */
  .shield-lightning { opacity: 0; }
  .state-mitigated .shield-lightning {
    opacity: 1;
    animation: lightningFlash 0.5s ease-out infinite;
  }
  @keyframes lightningFlash {
    0%,100% { opacity: 0.2; }
    50%     { opacity: 1;   }
  }

  /* ── Danger overlay when infected ───────────────────────── */
  .danger-overlay {
    position: absolute; inset: 0;
    background: radial-gradient(circle at 50% 45%,
        rgba(220,38,38,0.18) 0%, transparent 55%);
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.6s;
    z-index: 5;
  }
  .state-infected .danger-overlay { opacity: 1; animation: dangerPulse 1.4s ease-in-out infinite; }
  @keyframes dangerPulse {
    0%,100% { opacity: 0.5; }
    50%     { opacity: 1; }
  }
</style>

<div id="stage" class="state-__STATE__" data-target="__STATE__" style="--verdict-c: __VERDICT_C__;">

  <div id="verdict-bar">__VERDICT__</div>

  <div id="c-clone" class="corner">
    <div class="lbl">CLONE</div>
    <div class="val">__CLONE__</div>
  </div>
  <div id="c-stack" class="corner">
    <div class="lbl">STACK</div>
    <div class="val">__STACK__</div>
  </div>
  <div id="c-risk" class="corner">
    <div class="lbl">RISK</div>
    <div class="val">__RISK__/100</div>
  </div>
  <div id="c-stats" class="corner">
    <div class="lbl">EVENTS</div>
    <div class="val">__CRITS__ / __TOTAL__</div>
  </div>

  <!-- Stage labels under the journey -->
  <div id="lbl-files"  class="stage-label">Source Files<span class="sub">your repo</span></div>
  <div id="lbl-folder" class="stage-label">Cloned Folder<span class="sub">isolated twin</span></div>
  <div id="lbl-virus"  class="stage-label">ᗧ Pacman Virus<span class="sub">live attack</span></div>
  <div id="lbl-shield" class="stage-label">Shield<span class="sub">mitigation</span></div>

  <div class="danger-overlay"></div>

  <svg class="journey" viewBox="0 0 1200 380" preserveAspectRatio="xMidYMid meet">

    <!-- ── Arrows connecting the 4 stations ────────────────── -->
    <!-- Arrow 1: files → folder -->
    <path class="arrow-path arr-1" d="M 200 190 L 350 190"/>
    <polygon class="arrow-head arr-1-head" points="350,180 365,190 350,200"/>

    <!-- Arrow 2: folder → pacman -->
    <path class="arrow-path arr-2" d="M 500 190 L 650 190"/>
    <polygon class="arrow-head arr-2-head" points="650,180 665,190 650,200"/>

    <!-- Arrow 3: pacman → shield (mitigation direction) -->
    <path class="arrow-path arr-3" d="M 800 190 L 950 190"/>
    <polygon class="arrow-head arr-3-head" points="950,180 965,190 950,200"/>

    <!-- ── Station 1: SOURCE FILES (small file stack) ──────── -->
    <circle class="station-ring ring-1" cx="140" cy="190" r="78"/>
    <!-- 3 file icons stacked -->
    <g transform="translate(140,190)">
      <!-- File 3 (back) -->
      <g transform="translate(8,-10)">
        <path d="M -20,-25 L 8,-25 L 20,-13 L 20,25 L -20,25 Z"
              fill="#94A3B8" stroke="#64748B" stroke-width="1.5"/>
        <path d="M 8,-25 L 8,-13 L 20,-13" fill="none" stroke="#64748B" stroke-width="1.5"/>
        <line x1="-14" y1="-5" x2="14" y2="-5" stroke="#475569" stroke-width="1.5"/>
        <line x1="-14" y1="3"  x2="14" y2="3"  stroke="#475569" stroke-width="1.5"/>
        <line x1="-14" y1="11" x2="8"  y2="11" stroke="#475569" stroke-width="1.5"/>
      </g>
      <!-- File 2 (middle) -->
      <g transform="translate(-2,0)">
        <path d="M -22,-28 L 6,-28 L 18,-16 L 18,28 L -22,28 Z"
              fill="#CBD5E1" stroke="#64748B" stroke-width="1.5"/>
        <path d="M 6,-28 L 6,-16 L 18,-16" fill="none" stroke="#64748B" stroke-width="1.5"/>
        <line x1="-16" y1="-8" x2="12" y2="-8" stroke="#475569" stroke-width="1.5"/>
        <line x1="-16" y1="0"  x2="12" y2="0"  stroke="#475569" stroke-width="1.5"/>
        <line x1="-16" y1="8"  x2="4"  y2="8"  stroke="#475569" stroke-width="1.5"/>
      </g>
      <!-- File 1 (front, highlighted) -->
      <g transform="translate(-14,10)">
        <path d="M -24,-32 L 4,-32 L 16,-20 L 16,32 L -24,32 Z"
              fill="#F1F5F9" stroke="#3B82F6" stroke-width="1.8"/>
        <path d="M 4,-32 L 4,-20 L 16,-20" fill="none" stroke="#3B82F6" stroke-width="1.8"/>
        <line x1="-18" y1="-12" x2="10" y2="-12" stroke="#1E40AF" stroke-width="1.8"/>
        <line x1="-18" y1="-4"  x2="10" y2="-4"  stroke="#1E40AF" stroke-width="1.8"/>
        <line x1="-18" y1="4"   x2="10" y2="4"   stroke="#1E40AF" stroke-width="1.8"/>
        <line x1="-18" y1="12"  x2="2"  y2="12"  stroke="#1E40AF" stroke-width="1.8"/>
      </g>
    </g>

    <!-- ── Flying file particles travelling on arrow 1 ─────── -->
    <g transform="translate(200,190)">
      <g class="flying-file">
        <rect x="-7" y="-9" width="14" height="18" rx="2"
              fill="#F1F5F9" stroke="#3B82F6" stroke-width="1.4"/>
        <line x1="-4" y1="-3" x2="4" y2="-3" stroke="#1E40AF" stroke-width="1.2"/>
        <line x1="-4" y1="1"  x2="4" y2="1"  stroke="#1E40AF" stroke-width="1.2"/>
        <line x1="-4" y1="5"  x2="2" y2="5"  stroke="#1E40AF" stroke-width="1.2"/>
      </g>
      <g class="flying-file delay-1">
        <rect x="-7" y="-9" width="14" height="18" rx="2"
              fill="#F1F5F9" stroke="#3B82F6" stroke-width="1.4"/>
        <line x1="-4" y1="-3" x2="4" y2="-3" stroke="#1E40AF" stroke-width="1.2"/>
        <line x1="-4" y1="1"  x2="4" y2="1"  stroke="#1E40AF" stroke-width="1.2"/>
      </g>
      <g class="flying-file delay-2">
        <rect x="-7" y="-9" width="14" height="18" rx="2"
              fill="#F1F5F9" stroke="#3B82F6" stroke-width="1.4"/>
        <line x1="-4" y1="-3" x2="4" y2="-3" stroke="#1E40AF" stroke-width="1.2"/>
        <line x1="-4" y1="1"  x2="4" y2="1"  stroke="#1E40AF" stroke-width="1.2"/>
      </g>
      <g class="flying-file delay-3">
        <rect x="-7" y="-9" width="14" height="18" rx="2"
              fill="#F1F5F9" stroke="#3B82F6" stroke-width="1.4"/>
        <line x1="-4" y1="-3" x2="4" y2="-3" stroke="#1E40AF" stroke-width="1.2"/>
        <line x1="-4" y1="1"  x2="4" y2="1"  stroke="#1E40AF" stroke-width="1.2"/>
      </g>
    </g>

    <!-- ── Station 2: CLONE FOLDER (dark navy, fills up) ───── -->
    <circle class="station-ring ring-2" cx="420" cy="190" r="78"/>
    <g transform="translate(420,190)">
      <!-- Folder tab (top) -->
      <path class="folder-tab"
            d="M -52,-42 L -18,-42 L -10,-32 L 52,-32 L 52,-20 L -52,-20 Z"
            stroke-width="2"/>
      <!-- Folder body -->
      <rect class="folder-body" x="-52" y="-22" width="104" height="60" rx="4"
            stroke-width="2"/>
      <!-- Files inside folder (visibility driven by state) -->
      <g>
        <rect class="folder-file ff-1" x="-40" y="-10" width="20" height="26" rx="2"
              fill="#F1F5F9"/>
        <rect class="folder-file ff-2" x="-15" y="-10" width="20" height="26" rx="2"
              fill="#F1F5F9"/>
        <rect class="folder-file ff-3" x="10"  y="-10" width="20" height="26" rx="2"
              fill="#F1F5F9"/>
      </g>
      <!-- Skull warning shown on infected -->
      <g class="skull-warn" style="opacity:0; transition:opacity 0.5s">
        <circle cx="0" cy="-50" r="13" fill="#FEE2E2" stroke="#DC2626" stroke-width="2"/>
        <circle cx="-4" cy="-52" r="2" fill="#0F172A"/>
        <circle cx="4"  cy="-52" r="2" fill="#0F172A"/>
        <path d="M -5,-45 L 5,-45" stroke="#0F172A" stroke-width="1.5"/>
      </g>
    </g>

    <!-- ── Station 3: PACMAN VIRUS ────────────────────────── -->
    <circle class="station-ring ring-3" cx="720" cy="190" r="78"/>
    <g class="pacman-group">
      <!-- Top half of pacman body -->
      <path class="pacman-top"
            d="M 720,190 L 720,135 A 55,55 0 0,1 775,190 Z"
            fill="#FACC15" stroke="#A16207" stroke-width="2.5"/>
      <!-- Bottom half of pacman body -->
      <path class="pacman-bottom"
            d="M 720,190 L 720,245 A 55,55 0 0,0 775,190 Z"
            fill="#FACC15" stroke="#A16207" stroke-width="2.5"/>
      <!-- Back arc (closed side) -->
      <path d="M 720,135 A 55,55 0 1,0 720,245"
            fill="#FACC15" stroke="#A16207" stroke-width="2.5"/>
      <!-- Eye -->
      <circle class="pac-eye" cx="712" cy="160" r="6"/>
      <!-- X eye for death state -->
      <g class="pac-eye-x">
        <line x1="706" y1="154" x2="718" y2="166"/>
        <line x1="718" y1="154" x2="706" y2="166"/>
      </g>
    </g>

    <!-- ── Station 4: SHIELD (umbrella + gear + key) ──────── -->
    <circle class="station-ring ring-4" cx="1020" cy="190" r="78"/>
    <g class="shield-group" transform="translate(1020,190)">
      <!-- Umbrella canopy (orange/yellow with ribs) -->
      <path d="M -52,-15 A 52,40 0 0,1 52,-15 Z"
            fill="#FACC15" stroke="#0F172A" stroke-width="2.5"/>
      <!-- Umbrella ribs -->
      <path d="M -52,-15 Q -26,-50 0,-55 Q 26,-50 52,-15"
            fill="none" stroke="#0F172A" stroke-width="2"/>
      <path d="M -30,-15 Q -15,-46 0,-50"
            fill="none" stroke="#0F172A" stroke-width="1.5" opacity="0.7"/>
      <path d="M 30,-15 Q 15,-46 0,-50"
            fill="none" stroke="#0F172A" stroke-width="1.5" opacity="0.7"/>
      <!-- Umbrella tip -->
      <rect x="-3" y="-58" width="6" height="6" fill="#3B82F6" stroke="#0F172A" stroke-width="1.5"/>
      <!-- Umbrella handle going down -->
      <line x1="0" y1="-15" x2="0" y2="-2"
            stroke="#0F172A" stroke-width="3"/>

      <!-- Gear body -->
      <g transform="translate(0,18)">
        <!-- 8 gear teeth -->
        <g fill="#22C55E" stroke="#0F172A" stroke-width="2">
          <rect x="-5" y="-38" width="10" height="10"/>
          <rect x="-5" y="28"  width="10" height="10"/>
          <rect x="-38" y="-5" width="10" height="10"/>
          <rect x="28"  y="-5" width="10" height="10"/>
          <rect x="-30" y="-30" width="10" height="10" transform="rotate(45)"/>
          <rect x="20"  y="-30" width="10" height="10" transform="rotate(45)"/>
          <rect x="-30" y="20"  width="10" height="10" transform="rotate(45)"/>
          <rect x="20"  y="20"  width="10" height="10" transform="rotate(45)"/>
        </g>
        <!-- Gear body circle -->
        <circle r="28" fill="#22C55E" stroke="#0F172A" stroke-width="2.5"/>
        <!-- Inner white circle (key cutout) -->
        <circle r="16" fill="#F8FAFC" stroke="#0F172A" stroke-width="2"/>
        <!-- Key shaft -->
        <rect x="-3" y="-12" width="6" height="22" fill="#3B82F6" stroke="#0F172A" stroke-width="1.5"/>
        <!-- Key teeth -->
        <rect x="3" y="3"  width="5" height="3" fill="#3B82F6" stroke="#0F172A" stroke-width="1.2"/>
        <rect x="3" y="8"  width="3" height="3" fill="#3B82F6" stroke="#0F172A" stroke-width="1.2"/>
      </g>

      <!-- Lightning bolt that fires on mitigation -->
      <g class="shield-lightning">
        <polygon points="-70,-30 -50,0 -60,0 -45,30 -55,5 -50,5 -70,-30"
                 fill="#FBBF24" stroke="#A16207" stroke-width="1.5"
                 style="filter: drop-shadow(0 0 8px #FBBF24)"/>
      </g>
    </g>

  </svg>
</div>

<script>
  // v33: STEP-BY-STEP ANIMATION through all 5 stages.
  // User feedback: animation was stopping at 2 stages. Now we walk the
  // sequence idle → approaching → attacking → infected → mitigated/safe
  // and *land* on the verdict state. Each step holds for ~1.8 s so the
  // viewer sees the Pacman approach, chomp, and shield activation as a
  // narrative rather than a static end-state.
  (function(){
    const stage = document.getElementById('stage');
    if (!stage) return;
    const target = stage.dataset.target || 'idle';
    const SEQ = ['idle','approaching','attacking','infected','mitigated'];
    const STEP_MS = 1800;
    // Cut the sequence at the target — if verdict is infected, we stop
    // there; if mitigated, we walk through infected first then shield.
    const idx = SEQ.indexOf(target);
    const walk = idx < 0 ? ['idle', target] : SEQ.slice(0, idx + 1);
    if (walk.length <= 1) return;  // nothing to animate

    let step = 0;
    const applyState = (s) => {
      // Drop existing state-* class, add the new one
      SEQ.forEach(x => stage.classList.remove('state-' + x));
      stage.classList.add('state-' + s);
      // Skull pulse on infected
      document.querySelectorAll('.skull-warn').forEach(el => {
        el.style.opacity = (s === 'infected' ? '1' : '0');
      });
    };

    // Show idle for a brief breath, then march through
    applyState('idle');
    const tick = () => {
      step += 1;
      if (step >= walk.length) return;     // landed on verdict
      applyState(walk[step]);
      setTimeout(tick, STEP_MS);
    };
    setTimeout(tick, STEP_MS);

    // Replay button — click anywhere on the stage to restart the walk
    stage.style.cursor = 'pointer';
    stage.title = 'Click to replay animation';
    stage.addEventListener('click', () => {
      step = 0;
      applyState('idle');
      setTimeout(tick, STEP_MS);
    });
  })();
</script>
"""
