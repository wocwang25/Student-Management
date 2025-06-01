(function() {
    'use strict';
    
    console.log("Auto dismiss alerts script loaded for Django 5 + Jazzmin 3.0.1");
    
    // Cấu hình
    const CONFIG = {
        AUTO_DISMISS_TIME: 5000, // 5 giây
        UPDATE_INTERVAL: 100,    // Cập nhật mỗi 100ms
        FADE_DURATION: 300       // Thời gian fade out
    };
    
    // Theo dõi các alerts đã được xử lý
    const processedAlerts = new WeakSet();
    
    function createCountdownElements() {
        const countdownSpan = document.createElement('span');
        countdownSpan.className = 'countdown-timer';
        countdownSpan.textContent = Math.ceil(CONFIG.AUTO_DISMISS_TIME / 1000) + 's';
        
        const progressBar = document.createElement('div');
        progressBar.className = 'countdown-progress';
        progressBar.style.width = '100%';
        
        return { countdownSpan, progressBar };
    }
    
    function setupSingleAlert(alert) {
        // Kiểm tra xem alert đã được xử lý chưa
        if (processedAlerts.has(alert)) {
            return;
        }
        
        console.log("Setting up auto-dismiss for alert:", alert);
        processedAlerts.add(alert);
        
        // Tìm nút đóng với các selector phù hợp với Jazzmin
        const closeButton = alert.querySelector('.btn-close, .close, [data-dismiss="alert"], [data-bs-dismiss="alert"], button[aria-label="Close"]');
        
        if (!closeButton) {
            console.log("No close button found for alert, skipping auto-dismiss");
            return;
        }
        
        // Tạo các elements countdown
        const { countdownSpan, progressBar } = createCountdownElements();
        
        // Đảm bảo alert có position relative
        const computedStyle = window.getComputedStyle(alert);
        if (computedStyle.position === 'static') {
            alert.style.position = 'relative';
        }
        
        // Thêm elements vào alert
        if (closeButton.parentNode) {
            closeButton.parentNode.insertBefore(countdownSpan, closeButton);
        } else {
            alert.appendChild(countdownSpan);
        }
        alert.appendChild(progressBar);
        
        // Biến trạng thái
        let timeLeft = CONFIG.AUTO_DISMISS_TIME;
        let isPaused = false;
        let timer = null;
        
        // Hàm cập nhật countdown
        function updateCountdown() {
            if (isPaused) return;
            
            timeLeft -= CONFIG.UPDATE_INTERVAL;
            
            // Cập nhật progress bar
            const percentLeft = Math.max(0, (timeLeft / CONFIG.AUTO_DISMISS_TIME) * 100);
            progressBar.style.width = percentLeft + '%';
            
            // Cập nhật text
            const secondsLeft = Math.max(0, Math.ceil(timeLeft / 1000));
            countdownSpan.textContent = secondsLeft + 's';
            
            // Kiểm tra hết thời gian
            if (timeLeft <= 0) {
                clearInterval(timer);
                dismissAlert(alert, closeButton);
            }
        }
        
        // Hàm đóng alert
        function dismissAlert(alertElement, button) {
            try {
                // Thử click vào nút đóng trước
                if (button && typeof button.click === 'function') {
                    button.click();
                } else {
                    // Fallback: ẩn alert bằng cách thủ công
                    alertElement.style.transition = `opacity ${CONFIG.FADE_DURATION}ms ease`;
                    alertElement.style.opacity = '0';
                    
                    setTimeout(() => {
                        if (alertElement.parentNode) {
                            alertElement.parentNode.removeChild(alertElement);
                        }
                    }, CONFIG.FADE_DURATION);
                }
            } catch (error) {
                console.error("Error dismissing alert:", error);
            }
        }
        
        // Bắt đầu timer
        timer = setInterval(updateCountdown, CONFIG.UPDATE_INTERVAL);
        
        // Event listeners cho pause/resume
        alert.addEventListener('mouseenter', function() {
            isPaused = true;
            alert.classList.add('paused');
            countdownSpan.textContent = '⏸️';
        });
        
        alert.addEventListener('mouseleave', function() {
            isPaused = false;
            alert.classList.remove('paused');
        });
        
        // Cleanup khi alert bị đóng thủ công
        const cleanupTimer = () => {
            if (timer) {
                clearInterval(timer);
                timer = null;
            }
        };
        
        if (closeButton) {
            closeButton.addEventListener('click', cleanupTimer);
        }
        
        // Observer để cleanup khi alert bị remove
        const removalObserver = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                mutation.removedNodes.forEach(function(node) {
                    if (node === alert) {
                        cleanupTimer();
                        removalObserver.disconnect();
                    }
                });
            });
        });
        
        if (alert.parentNode) {
            removalObserver.observe(alert.parentNode, { childList: true });
        }
    }
    
    function initializeAlerts() {
        // Các selector cho alerts trong Jazzmin
        const alertSelectors = [
            '.alert',
            '.alert-dismissible',
            '.messages .alert',
            '.django-messages .alert',
            '[class*="alert-"]'
        ];
        
        alertSelectors.forEach(selector => {
            const alerts = document.querySelectorAll(selector + ':not(.no-auto-dismiss)');
            alerts.forEach(setupSingleAlert);
        });
    }
    
    // Khởi tạo khi DOM ready
    function onDOMReady() {
        console.log("DOM ready, initializing alerts");
        initializeAlerts();
    }
    
    // Chạy ngay nếu DOM đã sẵn sàng
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', onDOMReady);
    } else {
        // DOM đã sẵn sàng, chạy ngay
        onDOMReady();
    }
    
    // Observer cho alerts mới được thêm động
    const observer = new MutationObserver(function(mutations) {
        let shouldReinit = false;
        
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Kiểm tra nếu node mới là alert
                        if (node.matches && (
                            node.matches('.alert') || 
                            node.matches('[class*="alert-"]')
                        )) {
                            shouldReinit = true;
                        }
                        // Hoặc chứa alerts
                        else if (node.querySelector && node.querySelector('.alert')) {
                            shouldReinit = true;
                        }
                    }
                });
            }
        });
        
        if (shouldReinit) {
            // Delay nhỏ để đảm bảo DOM đã ổn định
            setTimeout(initializeAlerts, 100);
        }
    });
    
    // Bắt đầu observe
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Thêm vào global scope để debug
    window.autoDismissAlerts = {
        reinitialize: initializeAlerts,
        config: CONFIG
    };
    
})();