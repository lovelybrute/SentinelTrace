import { useEffect } from 'react';

const INTERACTIVE_SELECTOR = [
  'button',
  'a',
  '[role="button"]',
  '.panel',
  '.dashboard-glass-panel',
  '.metric-glass-card',
  '.quick-action-glass',
  '.sidebar-item',
  '[data-water-reactive="true"]',
].join(',');

/**
 * Adds a lightweight water-bubble response to pointer interactions without
 * changing component layout or intercepting clicks.
 */
export function WaterInteraction() {
  useEffect(() => {
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion) return;

    const handlePointerDown = (event: PointerEvent) => {
      const source = event.target;
      if (!(source instanceof Element)) return;

      const interactive = source.closest(INTERACTIVE_SELECTOR);
      if (!interactive || interactive.matches(':disabled, [aria-disabled="true"]')) return;

      const bubble = document.createElement('span');
      bubble.className = 'water-touch-bubble';
      bubble.style.left = `${event.clientX}px`;
      bubble.style.top = `${event.clientY}px`;
      bubble.setAttribute('aria-hidden', 'true');

      for (let index = 0; index < 3; index += 1) {
        const droplet = document.createElement('i');
        droplet.style.setProperty('--drop-angle', `${index * 120 + 18}deg`);
        droplet.style.setProperty('--drop-distance', `${22 + index * 5}px`);
        bubble.appendChild(droplet);
      }

      document.body.appendChild(bubble);
      window.setTimeout(() => bubble.remove(), 900);
    };

    document.addEventListener('pointerdown', handlePointerDown, { passive: true });
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, []);

  return null;
}
