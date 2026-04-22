/* main.js — Secure Document Sharing System */

document.addEventListener('DOMContentLoaded', () => {

  /* ── Auto-dismiss alerts after 5s ───────────────────────────────────── */
  document.querySelectorAll('.alert').forEach(el => {
    setTimeout(() => {
      el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      el.style.opacity = '0';
      el.style.transform = 'translateY(-6px)';
      setTimeout(() => el.remove(), 500);
    }, 5000);
  });

  /* ── Password strength meter ─────────────────────────────────────────── */
  const pwInput = document.getElementById('password');
  const strengthBar = document.getElementById('strength-bar');
  const strengthText = document.getElementById('strength-text');

  if (pwInput && strengthBar) {
    pwInput.addEventListener('input', () => {
      const val = pwInput.value;
      let score = 0;
      if (val.length >= 12) score++;
      if (/[A-Z]/.test(val)) score++;
      if (/[a-z]/.test(val)) score++;
      if (/[0-9]/.test(val)) score++;
      if (/[!@#$%^&*]/.test(val)) score++;

      const levels = [
        { label: '',         color: 'transparent',   width: '0%'   },
        { label: 'Weak',     color: '#ef4444',        width: '20%'  },
        { label: 'Weak',     color: '#f97316',        width: '40%'  },
        { label: 'Fair',     color: '#f59e0b',        width: '60%'  },
        { label: 'Good',     color: '#84cc16',        width: '80%'  },
        { label: 'Strong',   color: '#22c55e',        width: '100%' },
      ];

      const l = levels[score];
      strengthBar.style.width = l.width;
      strengthBar.style.background = l.color;
      if (strengthText) {
        strengthText.textContent = l.label;
        strengthText.style.color = l.color;
      }
    });
  }

  /* ── Confirm dangerous actions ───────────────────────────────────────── */
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', e => {
      const msg = el.dataset.confirm || 'Are you sure?';
      if (!confirm(msg)) e.preventDefault();
    });
  });

  /* ── Active nav link highlight ───────────────────────────────────────── */
  const path = window.location.pathname;
  document.querySelectorAll('.nav-links a').forEach(a => {
    if (a.getAttribute('href') && path.startsWith(a.getAttribute('href')) && a.getAttribute('href') !== '/') {
      a.classList.add('active');
    }
  });

  /* ── File input label update ─────────────────────────────────────────── */
  document.querySelectorAll('input[type="file"]').forEach(input => {
    input.addEventListener('change', () => {
      const label = input.nextElementSibling;
      if (label && label.classList.contains('file-label')) {
        label.textContent = input.files[0]?.name || 'No file chosen';
      }
    });
  });

  /* ── Animate table rows on load ──────────────────────────────────────── */
  document.querySelectorAll('tbody tr').forEach((row, i) => {
    row.style.animation = `fadeUp 0.25s ${i * 0.04}s ease both`;
  });

  /* ── Session timeout countdown in nav ───────────────────────────────── */
  const timerEl = document.getElementById('session-timer');
  if (timerEl) {
    let seconds = parseInt(timerEl.dataset.seconds || '1800', 10);
    const fmt = s => `${String(Math.floor(s / 60)).padStart(2,'0')}:${String(s % 60).padStart(2,'0')}`;
    timerEl.textContent = fmt(seconds);
    const interval = setInterval(() => {
      seconds--;
      if (seconds <= 0) {
        clearInterval(interval);
        timerEl.textContent = '00:00';
        timerEl.style.color = 'var(--danger)';
      } else {
        timerEl.textContent = fmt(seconds);
        if (seconds < 300) timerEl.style.color = 'var(--warning)';
      }
    }, 1000);
  }

  /* ── Copy text utility ───────────────────────────────────────────────── */
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.copy).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1500);
      });
    });
  });

});