/**
 * TWEEK Launch Page - Interactive Elements
 * "GAH! Because paranoia is a feature, not a bug"
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all components
    initParticles();
    initScrollEffects();
    initTerminalTyping();
    initCounterAnimation();
});

/**
 * Floating Coffee Particles
 * Creates ambient floating particles for the paranoid atmosphere
 */
function initParticles() {
    const container = document.getElementById('particles');
    const particleCount = 30;

    for (let i = 0; i < particleCount; i++) {
        createParticle(container, i);
    }
}

function createParticle(container, index) {
    const particle = document.createElement('div');
    particle.className = 'particle';

    // Random positioning
    particle.style.left = `${Math.random() * 100}%`;

    // Random size
    const size = 2 + Math.random() * 4;
    particle.style.width = `${size}px`;
    particle.style.height = `${size}px`;

    // Random animation delay and duration
    particle.style.animationDelay = `${Math.random() * 8}s`;
    particle.style.animationDuration = `${6 + Math.random() * 6}s`;

    // Random opacity
    particle.style.opacity = 0.2 + Math.random() * 0.4;

    container.appendChild(particle);
}

/**
 * Scroll-triggered animations
 * Reveals elements as they come into view
 */
function initScrollEffects() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');

                // Stagger children animations
                const children = entry.target.querySelectorAll('.stagger-child');
                children.forEach((child, index) => {
                    child.style.animationDelay = `${index * 0.1}s`;
                });
            }
        });
    }, observerOptions);

    // Observe all animatable elements
    document.querySelectorAll('.feature-card, .layer, .pricing-card').forEach(el => {
        el.classList.add('animate-on-scroll');
        observer.observe(el);
    });

    // Add CSS for scroll animations
    const style = document.createElement('style');
    style.textContent = `
        .animate-on-scroll {
            opacity: 0;
            transform: translateY(30px);
            transition: opacity 0.6s ease, transform 0.6s ease;
        }
        .animate-on-scroll.visible {
            opacity: 1;
            transform: translateY(0);
        }
    `;
    document.head.appendChild(style);
}

/**
 * Terminal typing effect
 * Simulates real-time terminal output
 */
function initTerminalTyping() {
    const terminal = document.querySelector('.terminal-output');
    if (!terminal) return;

    // Store original content
    const originalContent = terminal.innerHTML;

    // Add blinking cursor effect
    const cursorStyle = document.createElement('style');
    cursorStyle.textContent = `
        .terminal-cursor {
            display: inline-block;
            width: 8px;
            height: 14px;
            background: var(--accent-primary);
            animation: blink 1s step-end infinite;
            margin-left: 2px;
            vertical-align: middle;
        }
        @keyframes blink {
            50% { opacity: 0; }
        }
    `;
    document.head.appendChild(cursorStyle);

    // Observe terminal visibility
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateTerminal(terminal, originalContent);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    observer.observe(terminal);
}

function animateTerminal(terminal, content) {
    // Clear and prepare for animation
    terminal.innerHTML = '<span class="terminal-cursor"></span>';

    // Parse content into lines
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = content;
    const textContent = tempDiv.textContent;
    const lines = textContent.split('\n');

    let lineIndex = 0;
    let charIndex = 0;
    let output = '';

    // Simulate typing
    function type() {
        if (lineIndex < lines.length) {
            const line = lines[lineIndex];

            if (charIndex < line.length) {
                output += line[charIndex];
                charIndex++;
            } else {
                output += '\n';
                lineIndex++;
                charIndex = 0;
            }

            // Restore HTML formatting
            terminal.innerHTML = formatTerminalOutput(output) + '<span class="terminal-cursor"></span>';

            // Variable speed for realism
            const delay = charIndex === 0 ? 50 : (Math.random() * 10 + 5);
            setTimeout(type, delay);
        } else {
            // Typing complete, restore full formatted content
            terminal.innerHTML = content;
        }
    }

    // Start typing after a brief pause
    setTimeout(type, 500);
}

function formatTerminalOutput(text) {
    // Apply terminal styling classes
    return text
        .replace(/( ___________.*?\_\/ \_\| \_\/)/gs, '<span class="term-ascii">$1</span>')
        .replace(/(GAH!.*?Claude Code)/g, '<span class="term-dim">$1</span>')
        .replace(/(Component|Status|Details)/g, '<span class="term-label">$1</span>')
        .replace(/(Hook Integration|Keychain Vault|Sandbox \(exec\)|Execution Mode)/g, '<span class="term-cyan">$1</span>')
        .replace(/(✓ Active)/g, '<span class="term-green">$1</span>')
        .replace(/(cautious)/g, '<span class="term-yellow">$1</span>')
        .replace(/(Today:.*)/g, '<span class="term-dim">$1</span>');
}

/**
 * Counter animation for stats
 * Animates numbers from 0 to their target value
 */
function initCounterAnimation() {
    const stats = document.querySelectorAll('.stat-value');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCounter(entry.target);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    stats.forEach(stat => observer.observe(stat));
}

function animateCounter(element) {
    const text = element.textContent;
    const hasUnit = text.match(/[a-zA-Z]+$/);
    const unit = hasUnit ? hasUnit[0] : '';
    const target = parseInt(text);

    if (isNaN(target)) return;

    let current = 0;
    const duration = 1500;
    const increment = target / (duration / 16);
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function
        const easeOut = 1 - Math.pow(1 - progress, 3);
        current = Math.round(target * easeOut);

        element.textContent = current + unit;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

/**
 * Smooth scroll for navigation links
 */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

/**
 * Navigation background on scroll
 */
window.addEventListener('scroll', () => {
    const nav = document.querySelector('.nav');
    if (window.scrollY > 100) {
        nav.style.background = 'rgba(10, 10, 11, 0.95)';
    } else {
        nav.style.background = 'rgba(10, 10, 11, 0.8)';
    }
});

/**
 * GAH! Easter egg
 * Shake the title when hovering too long
 */
const gahTitle = document.querySelector('.title-line-1');
if (gahTitle) {
    let hoverTimeout;

    gahTitle.addEventListener('mouseenter', () => {
        hoverTimeout = setTimeout(() => {
            gahTitle.style.animationPlayState = 'running';
            // Play a subtle visual effect
            document.body.style.filter = 'hue-rotate(10deg)';
            setTimeout(() => {
                document.body.style.filter = 'none';
            }, 200);
        }, 500);
    });

    gahTitle.addEventListener('mouseleave', () => {
        clearTimeout(hoverTimeout);
        gahTitle.style.animationPlayState = 'paused';
    });
}

/**
 * Console easter egg for developers
 */
console.log(`
%c☕ TWEEK %cis watching...

%cGAH! You found the console!
Too much pressure on those credentials?
We've got you covered.

https://github.com/tmancino/tweek
`,
    'color: #f59e0b; font-size: 24px; font-weight: bold;',
    'color: #a1a1aa; font-size: 14px;',
    'color: #fafafa; font-size: 12px;'
);
