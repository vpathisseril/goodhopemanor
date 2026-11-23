'use strict';
const toggle = document.querySelector('.nav-toggle');
const menu = document.querySelector('.nav-menu');
if (toggle && menu) {
  if (!menu.id) menu.id = 'main-navigation';
  toggle.setAttribute('aria-controls', menu.id);
  toggle.addEventListener('click', () => {
    const open = menu.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(open));
    if (open) menu.querySelector('a')?.focus();
  });
  function closeNavigation() {
    menu.classList.remove('open');
    toggle.setAttribute('aria-expanded', 'false');
  }
  menu.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeNavigation));
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && menu.classList.contains('open')) {
      closeNavigation();
      toggle.focus();
    }
  });
}
const topButton = document.querySelector('.back-to-top');
if (topButton) {
  window.addEventListener(
    'scroll',
    () => topButton.classList.toggle('visible', window.scrollY > 400),
    {passive: true},
  );
  topButton.addEventListener('click', () => window.scrollTo({top: 0, behavior: 'smooth'}));
}
const galleryButtons = document.querySelectorAll('.gallery-button');
if (galleryButtons.length) {
  const overlay = document.createElement('div');
  overlay.className = 'lightbox';
  overlay.hidden = true;
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-label', 'Photo viewer');
  const closeButton = document.createElement('button');
  closeButton.type = 'button';
  closeButton.textContent = '×';
  closeButton.setAttribute('aria-label', 'Close image');
  const image = document.createElement('img');
  image.alt = '';
  overlay.append(closeButton, image);
  document.body.append(overlay);
  let lastFocused = null;
  function close() {
    overlay.hidden = true;
    image.removeAttribute('src');
    lastFocused?.focus();
  }
  galleryButtons.forEach((button) =>
    button.addEventListener('click', () => {
      lastFocused = button;
      image.src = button.dataset.full;
      image.alt = button.dataset.alt || '';
      overlay.hidden = false;
      closeButton.focus();
    }),
  );
  closeButton.addEventListener('click', close);
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) close();
  });
  window.addEventListener('keydown', (event) => {
    if (overlay.hidden) return;
    if (event.key === 'Escape') close();
    if (event.key === 'Tab') {
      event.preventDefault();
      closeButton.focus();
    }
  });
}
