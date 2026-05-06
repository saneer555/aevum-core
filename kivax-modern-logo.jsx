import { useState, useEffect } from "react";

// ══════════════════════════════════════════════════════════════
//  KIVAX — MODERN TECH LOGO
//  Jātakam Engineering:
//    Nakṣatra  → Mṛgaśīrṣa 4th Pāda (deer antler crown mark)
//    Birth 3   → Jupiter arch of expansion (crown base)
//    Life Path 7 → Void black depth, precision geometry
//    Mithuna   → Mercury emerald, twin symmetry
//    Lucky     → 4 gold nakshatra tip-stars, gold bindu
// ══════════════════════════════════════════════════════════════

const C = {
  void:       "#070A09",
  deep:       "#0F1512",
  slate:      "#192019",
  slateLight: "#253026",
  gold:       "#C8A020",
  goldBright: "#EEC233",
  goldGlow:   "rgba(200,160,32,0.28)",
  emerald:    "#00C87A",
  emerGlow:   "rgba(0,200,122,0.2)",
  white:      "#FFFFFF",
  bone:       "#F3F6F3",
  mist:       "#C8D4CC",
};

function useFont() {
  useEffect(() => {
    const el = document.createElement("link");
    el.rel = "stylesheet";
    el.href = "https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@600;700&display=swap";
    document.head.appendChild(el);
    return () => { try { document.head.removeChild(el); } catch(e) {} };
  }, []);
}

// ─── MARK SVG ──────────────────────────────────────────────────────────────
// ViewBox: 0 0 160 155
// The Crown of Mṛgaśīrṣa:
//   • Two forked antler prongs per side (4 total = 4th Pāda)
//   • Arch base = Jupiter's arc of prosperity (Birth 3)
//   • 4 gold stars at prong tips = the nakshatra's actual stars
//   • 1 gold bindu at arch center = Jupiter blessing dot
// ──────────────────────────────────────────────────────────────────────────
function Mark({
  size       = 120,
  inkColor   = C.void,
  goldColor  = C.gold,
  bgFill     = "transparent",
  rounded    = false,
  glowOn     = false,
}) {
  const id = `mk${size}${inkColor.replace("#","")}`;
  const strokeW = 10.5;
  const tipR    = 5.2;
  const binduR  = 7.5;

  return (
    <svg
      width={size} height={size}
      viewBox="0 0 160 155"
      fill="none"
      style={{ display: "block", flexShrink: 0 }}
    >
      <defs>
        <filter id={`sg-${id}`} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3.5" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <filter id={`gg-${id}`} x="-80%" y="-80%" width="260%" height="260%">
          <feGaussianBlur stdDeviation="5" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <radialGradient id={`bg-${id}`} cx="50%" cy="45%" r="55%">
          <stop offset="0%" stopColor={
            bgFill === C.void || bgFill === C.deep || bgFill === C.slate
              ? "#1E2B22" : bgFill === C.gold ? "#D4AE38"
              : bgFill === C.emerald ? "#00E08A"
              : "#FFFFFF"
          }/>
          <stop offset="100%" stopColor={bgFill}/>
        </radialGradient>
      </defs>

      {/* Background */}
      {bgFill !== "transparent" && (
        <rect
          width="160" height="155"
          rx={rounded ? 30 : 0}
          fill={`url(#bg-${id})`}
        />
      )}

      {/* ── Crown mark ────────────────────────────────── */}
      <g
        stroke={inkColor}
        strokeWidth={strokeW}
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        filter={glowOn ? `url(#sg-${id})` : undefined}
      >
        {/* Base arch — Jupiter arc (birth number 3, expansion) */}
        <path d="M 42,106 C 42,132 118,132 118,106" />

        {/* Left stalk */}
        <line x1="42" y1="106" x2="42" y2="74" />

        {/* Left outer prong — wide sweep, Mṛgaśīrṣa star α */}
        <path d="M 42,74 C 25,55 14,35 11,16" />

        {/* Left inner prong — tighter, Mṛgaśīrṣa star β */}
        <path d="M 42,74 C 47,52 51,30 51,11" />

        {/* Right stalk */}
        <line x1="118" y1="106" x2="118" y2="74" />

        {/* Right outer prong — Mṛgaśīrṣa star α' */}
        <path d="M 118,74 C 135,55 146,35 149,16" />

        {/* Right inner prong — Mṛgaśīrṣa star β' */}
        <path d="M 118,74 C 113,52 109,30 109,11" />
      </g>

      {/* ── Gold elements ─────────────────────────────── */}
      {/* Bindu — Jupiter's center blessing */}
      <circle
        cx="80" cy="127" r={binduR}
        fill={goldColor}
        filter={glowOn ? `url(#gg-${id})` : undefined}
      />

      {/* 4 nakshatra tip stars */}
      {[
        [11,  16, tipR],
        [51,  11, tipR * 0.82],
        [109, 11, tipR * 0.82],
        [149, 16, tipR],
      ].map(([cx, cy, r], i) => (
        <circle
          key={i}
          cx={cx} cy={cy} r={r}
          fill={goldColor}
          opacity={0.78}
          filter={glowOn ? `url(#gg-${id})` : undefined}
        />
      ))}
    </svg>
  );
}

// ─── WORDMARK ──────────────────────────────────────────────────────────────
function Wordmark({ size = 56, inkColor = C.void, goldColor = C.gold, textColor = C.void, bg = "transparent", glowOn = false }) {
  return (
    <div style={{
      display: "flex", alignItems: "center",
      gap: Math.round(size * 0.2),
      background: bg,
      padding: bg !== "transparent" ? `${size * 0.28}px ${size * 0.4}px` : 0,
      borderRadius: 14,
    }}>
      <Mark size={size} inkColor={inkColor} goldColor={goldColor} bgFill="transparent" glowOn={glowOn} />
      <span style={{
        fontFamily: "'Chakra Petch', 'Courier New', monospace",
        fontWeight: 700,
        fontSize: Math.round(size * 0.62),
        letterSpacing: Math.round(size * 0.055),
        color: textColor,
        lineHeight: 1,
        paddingTop: 3,
        userSelect: "none",
      }}>
        KIVAX
      </span>
    </div>
  );
}

// ─── SHOWCASE APP ──────────────────────────────────────────────────────────
export default function KivaxLogoSystem() {
  useFont();
  const [activeTab, setActiveTab] = useState("marks");

  const tabs = [
    { id: "marks",     label: "Mark" },
    { id: "wordmarks", label: "Wordmark" },
    { id: "icons",     label: "App Icons" },
    { id: "palette",   label: "Palette" },
    { id: "story",     label: "Story" },
  ];

  const label = (txt) => (
    <div style={{
      fontFamily: "'Chakra Petch', monospace",
      fontSize: 9, letterSpacing: 3,
      color: C.slateLight, textTransform: "uppercase",
      marginTop: 12, textAlign: "center",
    }}>{txt}</div>
  );

  const Tile = ({ bg, children, minH = 200 }) => (
    <div style={{
      background: bg,
      borderRadius: 16,
      minHeight: minH,
      display: "flex", alignItems: "center", justifyContent: "center",
      border: (bg === C.white || bg === C.bone) ? `1px solid #DDEADA` : "none",
      flexWrap: "wrap", gap: 32,
      padding: "36px 28px",
    }}>
      {children}
    </div>
  );

  return (
    <div style={{
      background: C.void, minHeight: "100vh",
      padding: "52px 32px", boxSizing: "border-box",
      color: C.white,
    }}>
      <div style={{ maxWidth: 860, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: 48 }}>
          <div style={{
            fontFamily: "'Chakra Petch', monospace",
            fontSize: 9, letterSpacing: 5,
            color: C.gold, marginBottom: 12,
          }}>
            KIVAX — BRAND IDENTITY SYSTEM
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>
            <Mark size={52} inkColor={C.white} goldColor={C.gold} glowOn />
            <div>
              <div style={{
                fontFamily: "'Chakra Petch', monospace",
                fontWeight: 700, fontSize: 38,
                letterSpacing: 8, color: C.white, lineHeight: 1,
              }}>KIVAX</div>
              <div style={{ fontSize: 11, color: C.slateLight, fontFamily: "monospace", marginTop: 5, letterSpacing: 1 }}>
                Vaccinate Your Code
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 6, marginBottom: 36, flexWrap: "wrap" }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
              padding: "8px 18px",
              background: activeTab === t.id ? C.gold : "transparent",
              color: activeTab === t.id ? C.void : C.gold,
              border: `1px solid ${activeTab === t.id ? C.gold : C.slateLight}`,
              borderRadius: 6,
              fontFamily: "'Chakra Petch', monospace",
              fontSize: 11, letterSpacing: 2,
              cursor: "pointer", fontWeight: 700,
              textTransform: "uppercase", transition: "all 0.15s",
            }}>{t.label}</button>
          ))}
        </div>

        {/* ── MARKS TAB ───────────────────────────────────── */}
        {activeTab === "marks" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

            {/* Hero dark */}
            <div style={{ position: "relative" }}>
              <Tile bg={C.deep} minH={240}>
                <div style={{
                  position: "absolute", inset: 0, borderRadius: 16,
                  background: `radial-gradient(ellipse at 50% 60%, ${C.goldGlow} 0%, transparent 65%)`,
                  pointerEvents: "none",
                }}/>
                {[72, 120, 72].map((s, i) => (
                  <Mark key={i} size={s} inkColor={C.white} goldColor={C.gold} glowOn />
                ))}
              </Tile>
              {label("Dark primary — white + gold")}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
              <div>
                <Tile bg={C.bone}>
                  <Mark size={90} inkColor={C.void} goldColor={C.gold} />
                </Tile>
                {label("Light")}
              </div>
              <div>
                <Tile bg={C.deep}>
                  <Mark size={90} inkColor={C.emerald} goldColor={C.gold} glowOn />
                </Tile>
                {label("Emerald")}
              </div>
              <div>
                <Tile bg={C.void}>
                  <Mark size={90} inkColor={C.gold} goldColor={C.goldBright} glowOn />
                </Tile>
                {label("All Gold")}
              </div>
            </div>
          </div>
        )}

        {/* ── WORDMARKS TAB ───────────────────────────────── */}
        {activeTab === "wordmarks" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            {[
              { bg: C.deep,    ink: C.white,   gold: C.gold,      text: C.white,   glow: true,  lbl: "Dark · Primary" },
              { bg: C.bone,    ink: C.void,    gold: C.gold,      text: C.void,    glow: false, lbl: "Light · Secondary" },
              { bg: C.void,    ink: C.emerald, gold: C.gold,      text: C.emerald, glow: true,  lbl: "Emerald · Brand" },
              { bg: C.deep,    ink: C.gold,    gold: C.goldBright,text: C.gold,    glow: true,  lbl: "Gold · Premium" },
            ].map(v => (
              <div key={v.lbl}>
                <Tile bg={v.bg} minH={160}>
                  <Wordmark size={52} inkColor={v.ink} goldColor={v.gold} textColor={v.text} glowOn={v.glow} />
                </Tile>
                {label(v.lbl)}
              </div>
            ))}
            {/* Full width stacked */}
            <div style={{ gridColumn: "1 / -1" }}>
              <Tile bg={C.deep} minH={160}>
                <Wordmark size={72} inkColor={C.white} goldColor={C.gold} textColor={C.white} glowOn />
              </Tile>
              {label("Large — Hero / Landing Page")}
            </div>
          </div>
        )}

        {/* ── ICONS TAB ───────────────────────────────────── */}
        {activeTab === "icons" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            {/* Rounded squares */}
            <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
              {[
                { bg: C.void,    ink: C.white,   gold: C.gold      },
                { bg: C.gold,    ink: C.void,    gold: C.void      },
                { bg: C.emerald, ink: C.void,    gold: C.gold      },
                { bg: C.white,   ink: C.void,    gold: C.gold      },
              ].map((v, i) => (
                <div key={i} style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center" }}>
                  <Mark size={96} inkColor={v.ink} goldColor={v.gold} bgFill={v.bg} rounded />
                  <Mark size={64} inkColor={v.ink} goldColor={v.gold} bgFill={v.bg} rounded />
                  <Mark size={40} inkColor={v.ink} goldColor={v.gold} bgFill={v.bg} rounded />
                </div>
              ))}
            </div>

            {/* Size ramp */}
            <div style={{
              background: C.deep, borderRadius: 16,
              padding: "32px 24px",
              display: "flex", alignItems: "flex-end", gap: 28,
              flexWrap: "wrap",
              border: `1px solid ${C.slate}`,
            }}>
              {[16, 24, 32, 48, 64, 80, 96, 128].map(s => (
                <div key={s} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
                  <Mark size={s} inkColor={C.white} goldColor={C.gold} />
                  <span style={{ fontSize: 9, color: C.slateLight, fontFamily: "monospace", letterSpacing: 1 }}>{s}</span>
                </div>
              ))}
            </div>
            {label("All sizes — mark scales pixel-perfect")}
          </div>
        )}

        {/* ── PALETTE TAB ─────────────────────────────────── */}
        {activeTab === "palette" && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
            {[
              { name: "JUPITER GOLD",      hex: C.gold,       note: "Birth 3 · Wealth · Lucky" },
              { name: "GOLD BRIGHT",       hex: C.goldBright, note: "Prosperity Highlight" },
              { name: "VOID BLACK",        hex: C.void,       note: "Life Path 7 · Ground" },
              { name: "DEEP FOREST",       hex: C.deep,       note: "Secondary Background" },
              { name: "MERCURY EMERALD",   hex: C.emerald,    note: "Mithuna Rāśi · Brand" },
              { name: "NAKSHATRA WHITE",   hex: C.white,      note: "Light Theme · Purity" },
              { name: "BONE",              hex: C.bone,       note: "Off-White Background" },
              { name: "MIST",              hex: C.mist,       note: "Text on dark · Subtle" },
            ].map(c => (
              <div key={c.hex} style={{
                flex: "1 1 160px", minWidth: 160,
                borderRadius: 10, overflow: "hidden",
                border: `1px solid ${C.slate}`,
              }}>
                <div style={{ height: 60, background: c.hex }} />
                <div style={{ padding: "10px 12px", background: C.slate }}>
                  <div style={{ fontSize: 8, letterSpacing: 2.5, color: C.gold, fontFamily: "'Chakra Petch', monospace", marginBottom: 4 }}>
                    {c.name}
                  </div>
                  <div style={{ fontSize: 10, color: C.white, fontFamily: "monospace", marginBottom: 3 }}>{c.hex}</div>
                  <div style={{ fontSize: 9, color: C.mist, fontFamily: "monospace", lineHeight: 1.5 }}>{c.note}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── STORY TAB ───────────────────────────────────── */}
        {activeTab === "story" && (
          <div style={{
            background: C.slate, borderRadius: 16,
            padding: 32,
            display: "flex", gap: 36, flexWrap: "wrap",
            alignItems: "flex-start",
            border: `1px solid ${C.slateLight}`,
          }}>
            <div style={{ flexShrink: 0 }}>
              <Mark size={130} inkColor={C.white} goldColor={C.gold} glowOn />
            </div>
            <div style={{ flex: 1, minWidth: 240 }}>
              <div style={{
                fontFamily: "'Chakra Petch', monospace",
                fontSize: 9, letterSpacing: 4,
                color: C.gold, marginBottom: 20,
              }}>
                HIDDEN GEOMETRY
              </div>
              {[
                ["↑ 4 ANTLER PRONGS",   "Mṛgaśīrṣa 4th Pāda — each prong = one star in your birth nakshatra"],
                ["✦ 4 GOLD TIP STARS",  "The actual stars of Mṛgaśīrṣa, mapped to each antler tip"],
                ["⌒ CROWN ARCH",        "Jupiter's arc of expansion — Birth Number 3, infinite prosperity"],
                ["● GOLD BINDU",        "The prāṇa center — all money, luck, success flows from here"],
                ["║ TWIN STALKS",       "Mercury's twin channels — Mithuna duality, intelligence both sides"],
                ["⬡ CROWN FORM",        "6-point crown silhouette — lucky number 6 from your Jātakam"],
              ].map(([sym, desc]) => (
                <div key={sym} style={{ display: "flex", gap: 14, marginBottom: 14 }}>
                  <span style={{
                    fontFamily: "'Chakra Petch', monospace",
                    fontSize: 9, letterSpacing: 1.5,
                    color: C.gold, minWidth: 148,
                    flexShrink: 0, paddingTop: 1,
                  }}>{sym}</span>
                  <span style={{
                    fontSize: 10, color: C.mist,
                    lineHeight: 1.65, fontFamily: "monospace",
                  }}>{desc}</span>
                </div>
              ))}
              <div style={{
                marginTop: 24, padding: "14px 16px",
                background: C.void, borderRadius: 8,
                borderLeft: `3px solid ${C.gold}`,
              }}>
                <div style={{ fontSize: 10, color: C.gold, fontFamily: "'Chakra Petch', monospace", marginBottom: 6, letterSpacing: 2 }}>
                  WHY THIS IS YOUR LUCKY LOGO
                </div>
                <div style={{ fontSize: 10, color: C.mist, lineHeight: 1.7, fontFamily: "monospace" }}>
                  The crown silhouette is universally decoded as royalty, victory, and wealth —
                  yet its inner architecture is your Jātakam. Every time someone sees KIVAX,
                  they see success. Only you know they're seeing your birth nakshatra,
                  Jupiter's blessing, and your Life Path encoded in strokes.
                </div>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
