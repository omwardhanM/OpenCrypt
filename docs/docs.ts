/**
 * OpenCrypt Documentation Page Controller
 * - Theme Management (Light / Dark)
 * - Rock-Solid Sidebar Navigation & Scrollspy (Exact Topic/Subtopic Highlighting)
 * - Mobile Sidebar Drawer Open/Close
 * - Code Snippet Copy Action
 */

// ============================================================================
// 1. Theme Management (Sync with main app)
// ============================================================================
const themeToggleBtn = document.getElementById('btn-theme-toggle');
const themeIconUse = document.getElementById('theme-icon-use');
const themeText = document.getElementById('theme-text');

function initTheme(): void {
  const savedTheme = localStorage.getItem('opencrypt_theme');
  const activeTheme = savedTheme === 'dark' ? 'dark' : 'light';
  applyTheme(activeTheme);
}

function applyTheme(theme: string): void {
  if (theme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.body.classList.add('theme-dark');
    if (themeIconUse) themeIconUse.setAttribute('href', '#icon-sun');
    if (themeText) themeText.textContent = 'Light Mode';
    if (themeToggleBtn) themeToggleBtn.setAttribute('aria-label', 'Switch to Light Mode');
  } else {
    document.documentElement.setAttribute('data-theme', 'light');
    document.body.classList.remove('theme-dark');
    if (themeIconUse) themeIconUse.setAttribute('href', '#icon-moon');
    if (themeText) themeText.textContent = 'Dark Mode';
    if (themeToggleBtn) themeToggleBtn.setAttribute('aria-label', 'Switch to Dark Mode');
  }
}

if (themeToggleBtn) {
  themeToggleBtn.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const nextTheme = isLight ? 'dark' : 'light';
    localStorage.setItem('opencrypt_theme', nextTheme);
    applyTheme(nextTheme);
  });
}

// ============================================================================
// 2. Mobile Sidebar Drawer Controls
// ============================================================================
const menuToggleBtn = document.getElementById('btn-docs-menu');
const sidebarCloseBtn = document.getElementById('btn-docs-sidebar-close');
const sidebar = document.getElementById('docs-sidebar');
const sidebarBackdrop = document.getElementById('docs-sidebar-backdrop');

function openSidebar(): void {
  if (sidebar) sidebar.classList.add('open');
  if (sidebarBackdrop) sidebarBackdrop.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeSidebar(): void {
  if (sidebar) sidebar.classList.remove('open');
  if (sidebarBackdrop) sidebarBackdrop.classList.remove('open');
  document.body.style.overflow = '';
}

if (menuToggleBtn) menuToggleBtn.addEventListener('click', openSidebar);
if (sidebarCloseBtn) sidebarCloseBtn.addEventListener('click', closeSidebar);
if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', closeSidebar);

// ============================================================================
// 3. Robust Sidebar Navigation & Scrollspy
// ============================================================================
let isProgrammaticScrolling = false;
let scrollTimeout: number | undefined;

function setActiveId(activeId: string): void {
  const links = document.querySelectorAll<HTMLAnchorElement>('.docs-sidebar-nav a');

  // Reset active classes
  links.forEach((l) => l.classList.remove('active', 'parent-active'));

  const activeLink = document.querySelector<HTMLAnchorElement>(`.docs-sidebar-nav a[href="#${activeId}"]`);
  if (!activeLink) return;

  activeLink.classList.add('active');

  // If this active link is a subtopic, make its parent topic header parent-active
  const parentGroup = activeLink.closest('.sidebar-topic-group');
  if (parentGroup) {
    const parentHeader = parentGroup.querySelector<HTMLAnchorElement>('.sidebar-topic-link');
    if (parentHeader && parentHeader !== activeLink) {
      parentHeader.classList.add('parent-active');
    }
  }

  // Ensure active link is gently scrolled into view in the sidebar if needed
  if (sidebar && window.innerWidth > 992) {
    const linkRect = activeLink.getBoundingClientRect();
    const sidebarRect = sidebar.getBoundingClientRect();
    if (linkRect.top < sidebarRect.top + 20 || linkRect.bottom > sidebarRect.bottom - 20) {
      activeLink.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }
}

function updateScrollspy(): void {
  if (isProgrammaticScrolling) return;

  const links = Array.from(document.querySelectorAll<HTMLAnchorElement>('.docs-sidebar-nav a'));
  const targets = links
    .map((link) => {
      const id = link.getAttribute('href')?.replace('#', '');
      const el = id ? document.getElementById(id) : null;
      return { id, el, link };
    })
    .filter((item): item is { id: string; el: HTMLElement; link: HTMLAnchorElement } => item.el !== null);

  if (targets.length === 0) return;

  // 1. Check if user reached bottom of page -> always highlight the last section
  const scrollPosition = window.scrollY + window.innerHeight;
  const documentHeight = document.documentElement.scrollHeight;
  const isBottom = scrollPosition >= documentHeight - 50;

  if (isBottom) {
    const lastTarget = targets[targets.length - 1];
    setActiveId(lastTarget.id);
    return;
  }

  // 2. Find target closest to top threshold (100px below top)
  const headerOffset = 100;
  let currentId = targets[0].id;

  for (let i = 0; i < targets.length; i++) {
    const rect = targets[i].el.getBoundingClientRect();
    if (rect.top <= headerOffset) {
      currentId = targets[i].id;
    } else {
      break;
    }
  }

  setActiveId(currentId);
}

function initSidebarLinks(): void {
  const links = document.querySelectorAll<HTMLAnchorElement>('.docs-sidebar-nav a');

  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      const href = link.getAttribute('href');
      if (!href || !href.startsWith('#')) return;

      const targetId = href.slice(1);
      const targetEl = document.getElementById(targetId);
      if (!targetEl) return;

      e.preventDefault();

      // Immediately highlight clicked link & parent topic
      setActiveId(targetId);
      isProgrammaticScrolling = true;

      // Smooth scroll to position accounting for sticky header
      const headerHeight = 65;
      const targetTop = targetEl.getBoundingClientRect().top + window.scrollY - headerHeight;

      window.scrollTo({
        top: Math.max(0, targetTop),
        behavior: 'smooth',
      });

      // Update URL hash smoothly
      history.pushState(null, '', '#' + targetId);

      // Close mobile drawer if on mobile
      if (window.innerWidth <= 992) {
        closeSidebar();
      }

      // Re-enable scroll detection once smooth scroll finishes
      if (scrollTimeout) window.clearTimeout(scrollTimeout);
      scrollTimeout = window.setTimeout(() => {
        isProgrammaticScrolling = false;
        updateScrollspy();
      }, 650);
    });
  });
}

// Throttle scroll events with requestAnimationFrame
let scrollTicking = false;
window.addEventListener(
  'scroll',
  () => {
    if (!scrollTicking) {
      window.requestAnimationFrame(() => {
        updateScrollspy();
        scrollTicking = false;
      });
      scrollTicking = true;
    }
  },
  { passive: true }
);

// ============================================================================
// 4. Interactive Code Snippet Copy Buttons
// ============================================================================
document.querySelectorAll<HTMLButtonElement>('.docs-copy-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const targetId = btn.getAttribute('data-target');
    if (!targetId) return;
    const targetElement = document.getElementById(targetId);
    if (!targetElement) return;

    try {
      await navigator.clipboard.writeText(targetElement.textContent || '');
      const originalText = btn.textContent;
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = originalText;
        btn.classList.remove('copied');
      }, 2000);
    } catch {
      btn.textContent = 'Error';
    }
  });
});

// ============================================================================
// 5. Initialize on DOM load
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initSidebarLinks();

  if (window.location.hash) {
    const hashId = window.location.hash.replace('#', '');
    const targetEl = document.getElementById(hashId);
    if (targetEl) {
      setActiveId(hashId);
      setTimeout(() => {
        const headerHeight = 65;
        const targetTop = targetEl.getBoundingClientRect().top + window.scrollY - headerHeight;
        window.scrollTo({ top: Math.max(0, targetTop), behavior: 'smooth' });
      }, 100);
    } else {
      updateScrollspy();
    }
  } else {
    updateScrollspy();
  }
});
