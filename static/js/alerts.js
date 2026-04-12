/* ============================================
   ALERTS PAGE - FILTERING & MODAL LOGIC
   ============================================ */

// Filter state
let currentFilter = 'all';
let searchQuery = '';

// Filter alerts by type
function filterAlerts(filterType, btn) {
    currentFilter = filterType;
    
    // Update active button styling
    document.querySelectorAll('.chip').forEach(function(chip) {
        chip.classList.remove('active');
    });
    btn.classList.add('active');
    
    applyFilters();
}

// Apply search filter
function applySearchFilter() {
    searchQuery = document.getElementById('search-box').value.toLowerCase();
    applyFilters();
}

// Apply all filters to table rows
function applyFilters() {
    const rows = document.querySelectorAll('#alert-tbody tr');
    let visibleCount = 0;
    
    rows.forEach(function(row) {
        const type = (row.dataset.type || '').toLowerCase();
        const src = (row.dataset.src || '').toLowerCase();
        let isVisible = true;
        
        // Filter by attack type
        if (currentFilter === 'attack') {
            if (!row.classList.contains('row-attack')) isVisible = false;
        } else if (currentFilter !== 'all' && currentFilter !== 'attack') {
            if (type !== currentFilter.toLowerCase()) isVisible = false;
        }
        
        // Filter by search query
        if (isVisible && searchQuery) {
            if (!src.includes(searchQuery) && !type.includes(searchQuery)) {
                isVisible = false;
            }
        }
        
        row.style.display = isVisible ? '' : 'none';
        if (isVisible) visibleCount++;
    });
    
    // Update row count display
    const rowCountSpan = document.getElementById('row-count');
    if (rowCountSpan) {
        rowCountSpan.textContent = visibleCount + ' alert' + (visibleCount !== 1 ? 's' : '');
    }
}

// Export all alerts as CSV
function exportAllAlerts() {
    window.location.href = '/api/alerts/export?format=csv';
}

// Show alert detail modal
function showAlertDetail(alertId) {
    const alert = alertData.find(function(item) {
        return String(item.id) === String(alertId);
    });
    
    if (!alert) return;
    
    // Set modal title
    document.getElementById('modal-title').textContent = 'ALERT #' + alert.id + ' — ' + alert.attack_type;
    
    // Severity color mapping
    const severityColors = {
        'HIGH': 'var(--c-red)',
        'MEDIUM': 'var(--c-amber)',
        'LOW': 'var(--c-cyan)',
        'SAFE': 'var(--c-green)'
    };
    
    // Build detail grid
    const fields = [
        ['Source IP', alert.src_ip],
        ['Destination', alert.dst_ip],
        ['Protocol', alert.protocol],
        ['Timestamp', alert.timestamp],
        ['Attack Type', alert.attack_type],
        ['Severity', alert.severity],
        ['ML Score', alert.combined_score],
        ['ML Confidence', alert.ml_confidence],
        ['Packets', alert.packet_count],
        ['Rule Fired', alert.rule_fired]
    ];
    
    const modalGrid = document.getElementById('modal-grid');
    modalGrid.innerHTML = '';
    
    fields.forEach(function(field) {
        const colorValue = (field[0] === 'Severity' && severityColors[alert.severity]) ? 
                         severityColors[alert.severity] : 'inherit';
        const div = document.createElement('div');
        div.className = 'detail-cell';
        div.innerHTML = `
            <div class="detail-label">${field[0]}</div>
            <div class="detail-value" style="color: ${colorValue};">${field[1] || '—'}</div>
        `;
        modalGrid.appendChild(div);
    });
    
    // Build SHAP explanation section
    const explanation = alert.explanation || [];
    const attackColors = {
        'DoS': 'var(--c-red)',
        'Probe': 'var(--c-amber)',
        'R2L': 'var(--c-purple)',
        'U2R': 'var(--c-cyan)',
        'Normal': 'var(--c-green)'
    };
    const color = attackColors[alert.attack_type] || 'var(--c-cyan)';
    
    const shapDiv = document.getElementById('modal-shap');
    
    if (explanation.length === 0) {
        shapDiv.innerHTML = '<div style="font-size:.82rem;color:var(--t-4);">No SHAP data available for this alert.</div>';
    } else {
        let shapHtml = `
            <div class="shap-intro">
                SHAP — Why detected as <strong style="color: ${color};">${alert.attack_type}</strong>
            </div>
        `;
        
        explanation.forEach(function(exp) {
            const pct = Math.round(Math.abs(exp.impact) * 100);
            const sign = exp.impact >= 0 ? '+' : '';
            shapHtml += `
                <div class="shap-item">
                    <span class="shap-feat">${exp.feature}</span>
                    <div class="shap-track">
                        <div class="shap-fill" style="width: ${pct}%; background: ${color};"></div>
                    </div>
                    <span class="shap-score" style="color: ${color};">${sign}${exp.impact.toFixed(2)}</span>
                </div>
            `;
        });
        
        shapDiv.innerHTML = shapHtml;
    }
    
    // Open modal
    document.getElementById('modal').classList.add('open');
}

// Close modal
function closeModal(event) {
    if (!event || event.target === document.getElementById('modal')) {
        document.getElementById('modal').classList.remove('open');
    }
}

// Update summary statistics from real-time data
function updateSummaryStats() {
    fetch('/api/statistics')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.statistics) {
                const stats = data.statistics;
                document.getElementById('summary-total').textContent = stats.system?.alerts_generated || '0';
                
                if (stats.by_severity) {
                    document.getElementById('summary-high').textContent = stats.by_severity.High || '0';
                    document.getElementById('summary-medium').textContent = stats.by_severity.Medium || '0';
                    document.getElementById('summary-low').textContent = stats.by_severity.Low || '0';
                }
            }
        })
        .catch(error => console.error('Error fetching stats:', error));
}

// Socket.IO event handlers for live alerts
if (typeof socket !== 'undefined') {
    socket.on('connect', function() {
        console.log('[Alerts] Connected to NIDS server');
        const liveIndicator = document.getElementById('live-indicator');
        if (liveIndicator) liveIndicator.style.display = 'inline-block';
    });
    
    socket.on('capture_started', function() {
        const liveIndicator = document.getElementById('live-indicator');
        if (liveIndicator) liveIndicator.style.display = 'inline-block';
    });
    
    socket.on('capture_stopped', function() {
        const liveIndicator = document.getElementById('live-indicator');
        if (liveIndicator) liveIndicator.style.display = 'none';
    });
    
    socket.on('new_alert', function(alert) {
        // Add new alert to the table
        const tbody = document.getElementById('alert-tbody');
        const emptyState = document.getElementById('alerts-empty');
        
        if (emptyState) emptyState.style.display = 'none';
        
        const row = document.createElement('tr');
        row.className = alert.is_attack ? 'row-attack' : 'row-normal';
        row.setAttribute('data-type', alert.attack_type);
        row.setAttribute('data-src', alert.src_ip);
        row.setAttribute('data-id', alert.id);
        
        row.innerHTML = `
            <td class="mono-cell" style="color:var(--t-4);">${alert.id}</td>
            <td class="mono-cell">${new Date(alert.timestamp * 1000).toLocaleString()}</td>
            <td class="mono-cell">${alert.src_ip}</td>
            <td class="mono-cell" style="color:var(--t-3);">${alert.dst_ip || '-'}</td>
            <td class="mono-cell" style="color:var(--t-3);">${alert.protocol || 'TCP'}</td>
            <td><span class="badge b-${alert.attack_type?.toLowerCase()}">${alert.attack_type}</span></td>
            <td><span class="badge b-${alert.severity?.toLowerCase()}">${alert.severity}</span></td>
            <td class="mono-cell ${alert.is_attack ? 'score-attack' : 'score-normal'}">${(alert.confidence || 0).toFixed(3)}</td>
            <td class="rule-cell" title="${alert.rule_fired || '-'}">${alert.rule_fired || '-'}</td>
            <td><button class="btn-detail" onclick="showAlertDetail('${alert.id}')">Detail</button></td>
        `;
        
        tbody.prepend(row);
        
        // Keep only last 200 rows
        while (tbody.children.length > 200) {
            tbody.removeChild(tbody.lastChild);
        }
        
        // Update row count
        const rowCountSpan = document.getElementById('row-count');
        if (rowCountSpan) {
            const visibleRows = document.querySelectorAll('#alert-tbody tr:not([style*="display: none"])').length;
            rowCountSpan.textContent = visibleRows + ' alert' + (visibleRows !== 1 ? 's' : '');
        }
        
        // Update summary statistics
        updateSummaryStats();
        
        // Show browser notification if enabled
        if (Notification && Notification.permission === 'granted' && alert.severity === 'HIGH') {
            new Notification('🚨 NIDS Alert', {
                body: `${alert.attack_type} detected from ${alert.src_ip}`,
                icon: '/static/assets/logo.png'
            });
        }
    });
}

// Request notification permission
if (Notification && Notification.permission !== 'granted' && Notification.permission !== 'denied') {
    Notification.requestPermission();
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    updateSummaryStats();
    setInterval(updateSummaryStats, 15000);
});