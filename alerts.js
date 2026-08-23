// ============================================
// ALERTS SYSTEM
// ============================================

var AlertConfig = {
    duration: 6000,
    maxAlerts: 5,
    soundEnabled: true,
    position: 'top-right'
};

var AlertStyles = `
.toast-container {
    position: fixed;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 10px;
    max-width: 420px;
    min-width: 280px;
    pointer-events: none;
}

.toast-container.top-right {
    top: 20px;
    right: 20px;
}
.toast-container.top-left {
    top: 20px;
    left: 20px;
}
.toast-container.bottom-right {
    bottom: 20px;
    right: 20px;
}
.toast-container.bottom-left {
    bottom: 20px;
    left: 20px;
}

.toast {
    background: #1a1d27;
    border-left: 5px solid #dc2626;
    padding: 16px 20px;
    border-radius: 10px;
    box-shadow: 0 8px 30px rgba(0,0,0,0.8);
    animation: slideIn 0.4s ease;
    color: #e4e6eb;
    font-size: 0.95rem;
    font-family: 'Inter', 'Segoe UI', sans-serif;
    pointer-events: auto;
    transition: all 0.3s ease;
}

.toast:hover {
    transform: scale(1.02);
    box-shadow: 0 12px 40px rgba(0,0,0,0.9);
}

.toast.critical {
    border-left-color: #dc2626;
    background: #1a0a0a;
}
.toast.high {
    border-left-color: #eab308;
    background: #1a1a0a;
}
.toast.medium {
    border-left-color: #3b82f6;
    background: #0a0a1a;
}
.toast.low {
    border-left-color: #22c55e;
    background: #0a1a0e;
}

.toast .toast-icon {
    font-size: 1.4rem;
    margin-right: 12px;
}
.toast .toast-content {
    flex: 1;
}
.toast .toast-title {
    font-weight: 600;
    font-size: 1.05rem;
    margin-bottom: 4px;
}
.toast .toast-detail {
    color: #8892a8;
    font-size: 0.85rem;
}
.toast .toast-time {
    color: #667799;
    font-size: 0.7rem;
    margin-top: 6px;
}
.toast .toast-close {
    background: none;
    border: none;
    color: #667799;
    font-size: 1.2rem;
    cursor: pointer;
    padding: 0 5px;
    transition: 0.2s;
}
.toast .toast-close:hover {
    color: #e4e6eb;
}

.toast .toast-flex {
    display: flex;
    align-items: flex-start;
    gap: 12px;
}

@keyframes slideIn {
    from { opacity: 0; transform: translateX(60px); }
    to { opacity: 1; transform: translateX(0); }
}

@keyframes slideOut {
    from { opacity: 1; transform: translateX(0); }
    to { opacity: 0; transform: translateX(60px); }
}

.toast.exit {
    animation: slideOut 0.4s ease forwards;
}
`;

// ===== ALERT SYSTEM CLASS =====
var AlertSystem = function() {
    this.container = null;
    this.alertCount = 0;
    this.init();
};

AlertSystem.prototype.init = function() {
    var style = document.createElement('style');
    style.textContent = AlertStyles;
    document.head.appendChild(style);

    this.container = document.createElement('div');
    this.container.className = 'toast-container ' + AlertConfig.position;
    document.body.appendChild(this.container);
};

AlertSystem.prototype.show = function(title, detail, severity, icon) {
    severity = severity || 'high';
    icon = icon || '';

    if (this.container.children.length >= AlertConfig.maxAlerts) {
        var first = this.container.firstChild;
        if (first) this.removeToast(first);
    }

    var toast = document.createElement('div');
    toast.className = 'toast ' + severity.toLowerCase();

    var now = new Date();
    var timeStr = now.toLocaleTimeString();

    toast.innerHTML = '<div class="toast-flex">' +
        (icon ? '<span class="toast-icon">' + icon + '</span>' : '') +
        '<div class="toast-content">' +
        '<div class="toast-title">' + title + '</div>' +
        '<div class="toast-detail">' + detail + '</div>' +
        '<div class="toast-time">' + timeStr + '</div>' +
        '</div>' +
        '<button class="toast-close">x</button>' +
        '</div>';

    toast.querySelector('.toast-close').addEventListener('click', function() {
        if (this.closest) {
            var t = this.closest('.toast');
            if (t) t.click();
        }
    });

    toast.addEventListener('click', function() {
        var self = this;
        self.classList.add('exit');
        setTimeout(function() {
            if (self.parentNode) {
                self.remove();
            }
        }, 400);
    });

    this.container.appendChild(toast);
    this.alertCount++;

    var self = this;
    setTimeout(function() {
        if (toast.parentNode) {
            toast.classList.add('exit');
            setTimeout(function() {
                if (toast.parentNode) {
                    toast.remove();
                    self.alertCount--;
                }
            }, 400);
        }
    }, AlertConfig.duration);

    if (severity.toLowerCase() === 'critical' && AlertConfig.soundEnabled) {
        this.playSound();
    }

    return toast;
};

AlertSystem.prototype.removeToast = function(toast) {
    if (!toast || !toast.parentNode) return;
    toast.classList.add('exit');
    var self = this;
    setTimeout(function() {
        if (toast.parentNode) {
            toast.remove();
            self.alertCount--;
        }
    }, 400);
};

AlertSystem.prototype.clearAll = function() {
    var self = this;
    while (this.container.firstChild) {
        this.removeToast(this.container.firstChild);
    }
};

AlertSystem.prototype.playSound = function() {
    try {
        var ctx = new (window.AudioContext || window.webkitAudioContext)();
        var osc = ctx.createOscillator();
        var gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);

        osc.frequency.value = 800;
        gain.gain.value = 0.3;
        osc.start();

        setTimeout(function() {
            osc.frequency.value = 1000;
            gain.gain.value = 0.3;
        }, 150);

        setTimeout(function() {
            gain.gain.value = 0;
        }, 350);

        setTimeout(function() {
            osc.frequency.value = 900;
            gain.gain.value = 0.3;
        }, 450);

        setTimeout(function() {
            gain.gain.value = 0;
        }, 650);

        setTimeout(function() {
            ctx.close();
        }, 700);

    } catch (e) {
        console.log('Sound not available');
    }
};

AlertSystem.prototype.critical = function(title, detail, icon) {
    return this.show(title, detail, 'critical', icon || '');
};

AlertSystem.prototype.high = function(title, detail, icon) {
    return this.show(title, detail, 'high', icon || '');
};

AlertSystem.prototype.medium = function(title, detail, icon) {
    return this.show(title, detail, 'medium', icon || '');
};

AlertSystem.prototype.low = function(title, detail, icon) {
    return this.show(title, detail, 'low', icon || '');
};

AlertSystem.prototype.success = function(title, detail, icon) {
    return this.show(title, detail, 'low', icon || '');
};

// ============================================
// EXPORT
// ============================================
if (typeof window !== 'undefined') {
    window.AlertSystem = AlertSystem;
    window.alerts = new AlertSystem();
    console.log('Alerts System loaded');
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AlertSystem: AlertSystem };
}