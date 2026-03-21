/* ═══════════════════════════════════════════════════════════════════
   FlagVault CTF — ECDSA Nonce Reuse Attack · Challenge #C8
   ───────────────────────────────────────────────────────────────
   CHALLENGE VALUES
   ─────────────────
   n  = 115792089237316195423570985008687907852837564279074904382605163141518161494337

   r  = 1048512034789123498712034987120394871203948712039487120394871203948712
   s1 = 8239478120394871203948712039487120394871203948712039487120394871203948
   h1 = 4578120394871203948712039487120394871203948712039487120394871203948712
   s2 = 2394871203948712039487120394871203948712039487120394871203948712039487
   h2 = 9120394871203948712039487120394871203948712039487120394871203948712039

   ATTACK:
   k = (h1 - h2) * modinv(s1 - s2) mod n
   d = (s1*k - h1) * modinv(r) mod n

   RESULTS (verified):
   k = 81601600685952438273783630961332820140394226819011112003822364831803761217274
   d = 45108193149407035105904684046542306378302782122491144574305651107841380142253

   FLAG: FlagVault{45108193149407035105904684046542306378302782122491144574305651107841380142253}
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

/* ──────── Challenge constants ──────── */
const N  = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;
const R  = 1048512034789123498712034987120394871203948712039487120394871203948712n;
const S1 = 8239478120394871203948712039487120394871203948712039487120394871203948n;
const H1 = 4578120394871203948712039487120394871203948712039487120394871203948712n;
const S2 = 2394871203948712039487120394871203948712039487120394871203948712039487n;
const H2 = 9120394871203948712039487120394871203948712039487120394871203948712039n;

const KNOWN_K = 81601600685952438273783630961332820140394226819011112003822364831803761217274n;
const KNOWN_D = 45108193149407035105904684046542306378302782122491144574305651107841380142253n;
const FLAG    = `FlagVault{${KNOWN_D.toString()}}`;

/* ──────── BigInt modular inverse (Extended GCD) ──────── */
function modinv(a, m) {
  a = ((a % m) + m) % m;
  let [old_r, r]   = [a, m];
  let [old_s, s]   = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

/* ──────── State ──────── */
let recovered_k = null;
let recovered_d = null;

/* ──────── Solver toggles ──────── */
function toggleSlv(n) {
  const card = document.getElementById(`s${n}`);
  const body = document.getElementById(`s${n}b`);
  const tog  = document.getElementById(`s${n}t`);
  if (!card || card.classList.contains('locked')) return;
  const hidden = body.classList.toggle('hidden');
  if (tog && tog.textContent !== '🔒' && tog.textContent !== '✓') {
    tog.textContent = hidden ? '▶ Open' : '▼ Close';
  }
}

function unlockStep(n) {
  const card = document.getElementById(`s${n}`);
  const body = document.getElementById(`s${n}b`);
  const tog  = document.getElementById(`s${n}t`);
  const btn  = document.getElementById(`s${n}-btn`);
  if (!card) return;
  card.classList.remove('locked');
  card.classList.add('unlocked');
  if (body) body.classList.remove('hidden');
  if (btn)  btn.disabled = false;
  if (tog)  tog.textContent = '▼ Close';
}

function markDone(n) {
  document.getElementById(`s${n}`)?.classList.add('done');
  const tog = document.getElementById(`s${n}t`);
  if (tog) tog.textContent = '✓';
}

function showRes(n, html) {
  const el = document.getElementById(`s${n}-res`);
  if (el) { el.innerHTML = html; el.classList.remove('hidden'); }
}

/* ──────── Step 1: Recover k ──────── */
function runRecoverK() {
  const btn = document.getElementById('s1-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Computing…';

  setTimeout(() => {
    const diff_h = ((H1 - H2) % N + N) % N;
    const diff_s = ((S1 - S2) % N + N) % N;
    const k = (diff_h * modinv(diff_s, N)) % N;
    recovered_k = k;

    const ks = k.toString();
    showRes(1, `
      <div class="res-box">
        <div class="rb-f">diff_h = (h₁ − h₂) mod n = <span style="color:var(--accent3)">${diff_h.toString().substring(0,30)}…</span></div>
        <div class="rb-f">diff_s = (s₁ − s₂) mod n = <span style="color:var(--accent3)">${diff_s.toString().substring(0,30)}…</span></div>
        <div class="rb-f">k = diff_h × diff_s⁻¹ mod n</div>
        <div class="rb-f rb-hi">k = ${ks}</div>
        <div class="rb-f rb-ok">✓ k recovered (${ks.length} digits)</div>
      </div>`);

    btn.textContent = '✓ k Recovered';
    markDone(1);
    unlockStep(2);
  }, 80);
}

/* ──────── Step 2: Recover d ──────── */
function runRecoverD() {
  if (!recovered_k) return;
  const btn = document.getElementById('s2-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Computing…';

  setTimeout(() => {
    const k = recovered_k;
    const numerator = ((S1 * k - H1) % N + N) % N;
    const d = (numerator * modinv(R, N)) % N;
    recovered_d = d;

    const ds = d.toString();
    showRes(2, `
      <div class="res-box">
        <div class="rb-f">numerator = (s₁·k − h₁) mod n</div>
        <div class="rb-f">d = numerator × r⁻¹ mod n</div>
        <div class="rb-f rb-hi">d = ${ds}</div>
        <div class="rb-f rb-ok">✓ Private key recovered (${ds.length} digits)</div>
      </div>`);

    btn.textContent = '✓ d Recovered';
    markDone(2);
    unlockStep(3);
  }, 80);
}

/* ──────── Step 3: Verify ──────── */
function runVerify() {
  if (!recovered_k || !recovered_d) return;
  const btn = document.getElementById('s3-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Verifying…';

  setTimeout(() => {
    const k = recovered_k;
    const d = recovered_d;
    const k_inv = modinv(k, N);
    const s1_computed = (k_inv * ((H1 + R * d) % N)) % N;
    const s2_computed = (k_inv * ((H2 + R * d) % N)) % N;
    const ok1 = s1_computed === S1;
    const ok2 = s2_computed === S2;

    const s1s = S1.toString();
    const s2s = S2.toString();
    const s1c = s1_computed.toString();
    const s2c = s2_computed.toString();

    showRes(3, `
      <div class="res-box">
        <div class="rb-f">k⁻¹·(h₁ + r·d) mod n</div>
        <div class="rb-f rb-val">= ${s1c}</div>
        <div class="rb-f">Given s₁</div>
        <div class="rb-f rb-val">= ${s1s}</div>
        <div class="rb-f rb-check">Match: ${ok1 ? '✓ YES — s₁ verified!' : '✗ NO'}</div>
        <div class="rb-f" style="margin-top:.5rem">k⁻¹·(h₂ + r·d) mod n</div>
        <div class="rb-f rb-val">= ${s2c}</div>
        <div class="rb-f">Given s₂</div>
        <div class="rb-f rb-val">= ${s2s}</div>
        <div class="rb-f rb-check">Match: ${ok2 ? '✓ YES — s₂ verified!' : '✗ NO'}</div>
        ${ok1 && ok2 ? `<div class="rb-f rb-flag">FLAG: FlagVault{${d.toString()}}</div>` : ''}
      </div>`);

    btn.textContent = '✓ Verified';
    markDone(3);

    if (ok1 && ok2) setTimeout(revealFlag, 500);
  }, 80);
}

/* ──────── Flag reveal ──────── */
function revealFlag() {
  const wrap = document.getElementById('flag-reveal');
  if (!wrap || !wrap.classList.contains('hidden')) return;
  document.getElementById('fr-val').textContent = FLAG;
  wrap.classList.remove('hidden');
  setTimeout(() => wrap.scrollIntoView({ behavior: 'smooth', block: 'center' }), 300);
}

function copyFlag() {
  const v = document.getElementById('fr-val').textContent;
  const t = document.getElementById('copy-toast');
  navigator.clipboard.writeText(v).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = v; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
  });
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 2000);
}

/* ──────── Hints ──────── */
function toggleHint(n) {
  const b = document.getElementById(`h${n}b`);
  const t = document.getElementById(`h${n}t`);
  const h = b.classList.toggle('hidden');
  t.textContent = h ? '▼ Reveal' : '▲ Hide';
}

/* ──────── Submit ──────── */
function submitFlag() {
  const v = document.getElementById('flag-input').value.trim();
  const r = document.getElementById('flag-result');
  if (`FlagVault{${v}}` === FLAG) {
    r.className = 'submit-result correct';
    r.innerHTML = '✓ &nbsp;Correct! Flag accepted. +450 pts';
    revealFlag();
  } else {
    r.className = 'submit-result incorrect';
    r.innerHTML = '✗ &nbsp;Incorrect flag. Keep trying.';
  }
}

/* ──────── Boot ──────── */
document.addEventListener('DOMContentLoaded', () => {
  unlockStep(1);

  document.getElementById('flag-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitFlag();
  });

  console.log('%c📐 FlagVault CTF — ECDSA Nonce Reuse', 'font-size:14px;font-weight:bold;color:#00e8c8;');
  console.log('%cr1 == r2 → same k → private key leaks', 'color:#ff2d6b;font-family:monospace;');
  console.log('%ck = (h1-h2)*modinv(s1-s2) mod n', 'color:#b8cdd9;font-family:monospace;');
  console.log('%cd = (s1*k-h1)*modinv(r) mod n', 'color:#b8cdd9;font-family:monospace;');
  console.log(`%cFlag: ${FLAG}`, 'color:#f5a623;font-family:monospace;');
});
