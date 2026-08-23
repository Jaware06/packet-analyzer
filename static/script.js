/* ==========================================================================
   Packet Analyzer - Client-Side App Controller
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    // Current Active Analysis Data store (for exports)
    let currentAnalysis = null;
    let selectedFile = null;
    let liveSnifferInterval = null;

    // Elements
    const dropZone = document.getElementById('dropZone');
    const fileSelector = document.getElementById('fileSelector');
    const selectedFilename = document.getElementById('selectedFilename');
    const btnUploadAnalyze = document.getElementById('btnUploadAnalyze');
    const btnResetUpload = document.getElementById('btnResetUpload');
    const analysisResult = document.getElementById('analysisResult');
    
    // Tab Elements
    const tabPanes = document.querySelectorAll('.tab-pane');
    const menuItems = document.querySelectorAll('.menu-item');
    
    // Stats elements
    const statTotalPackets = document.getElementById('statTotalPackets');
    const statUniqueIps = document.getElementById('statUniqueIps');
    const statThreatCount = document.getElementById('statThreatCount');
    
    // Panel Containers
    const threatFeedContainer = document.getElementById('threatFeedContainer');
    const deviceTagContainer = document.getElementById('deviceTagContainer');
    const protocolDistributionContainer = document.getElementById('protocolDistributionContainer');
    
    // Inspector elements
    const packetTableBody = document.getElementById('packetTableBody');
    const packetSearch = document.getElementById('packetSearch');
    const protocolFilter = document.getElementById('protocolFilter');

    // Live Sniff elements
    const btnStartSniff = document.getElementById('btnStartSniff');
    const btnStopSniff = document.getElementById('btnStopSniff');
    const liveStatusDot = document.getElementById('liveStatusDot');
    const liveStatusText = document.getElementById('liveStatusText');
    const livePacketCounter = document.getElementById('livePacketCounter');
    const mockWarning = document.getElementById('mockWarning');
    const liveThreatContainer = document.getElementById('liveThreatContainer');
    const liveTerminalContainer = document.getElementById('liveTerminalContainer');

    // Export buttons
    const btnExportJSON = document.getElementById('btnExportJSON');
    const btnExportCSV = document.getElementById('btnExportCSV');

    // History elements
    const historyTableBody = document.getElementById('historyTableBody');
    const historyTabButton = document.getElementById('historyTabButton');

    // Alert container banner
    const alertContainer = document.getElementById('alertContainer');

    // ============================================
    // SYSTEM CLOCK
    // ============================================
    const systemClock = document.getElementById('systemClock');
    function updateClock() {
        const now = new Date();
        systemClock.textContent = now.toLocaleTimeString();
    }
    setInterval(updateClock, 1000);
    updateClock();

    // ============================================
    // TAB ROUTING MANAGEMENT
    // ============================================
    menuItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetPane = item.getAttribute('data-target');
            
            // Toggle active menu item
            menuItems.forEach(menu => menu.classList.remove('active'));
            item.classList.add('active');
            
            // Toggle active tab pane
            tabPanes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(targetPane).classList.add('active');

            // Hook for loading content when navigating
            if (targetPane === 'history-tab') {
                loadHistoryLogs();
            }
        });
    });

    // ============================================
    // ALERT UTILITIES
    // ============================================
    function displayAlert(message, type = 'success') {
        alertContainer.innerHTML = `
            <div class="alert-banner alert-banner-${type}">
                <span>${message}</span>
                <button class="alert-banner-close" onclick="this.parentElement.remove()">&times;</button>
            </div>
        `;
        // Auto remove after 5 seconds
        setTimeout(() => {
            const banner = alertContainer.querySelector('.alert-banner');
            if (banner) banner.remove();
        }, 5000);
    }

    // ============================================
    // FILE UPLOAD AND DRAG-DROP
    // ============================================
    dropZone.addEventListener('click', () => fileSelector.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    ['dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, () => dropZone.classList.remove('dragover'));
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer.files.length > 0) {
            handleFileSelection(e.dataTransfer.files[0]);
        }
    });

    fileSelector.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelection(e.target.files[0]);
        }
    });

    function handleFileSelection(file) {
        const ext = file.name.split('.').pop().toLowerCase();
        if (ext !== 'pcap' && ext !== 'pcapng') {
            displayAlert('Unsupported file format. Please upload .pcap or .pcapng files.', 'error');
            resetUploadSelection();
            return;
        }

        selectedFile = file;
        selectedFilename.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        btnUploadAnalyze.removeAttribute('disabled');
        dropZone.style.borderColor = 'var(--color-primary)';
    }

    btnResetUpload.addEventListener('click', (e) => {
        e.stopPropagation();
        resetUploadSelection();
    });

    function resetUploadSelection() {
        selectedFile = null;
        fileSelector.value = '';
        selectedFilename.textContent = 'No file chosen';
        btnUploadAnalyze.setAttribute('disabled', 'true');
        dropZone.style.borderColor = 'var(--border-color)';
    }

    btnUploadAnalyze.addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!selectedFile) return;

        // Visual loading state
        const originalText = btnUploadAnalyze.innerHTML;
        btnUploadAnalyze.innerHTML = '<span class="spinner" style="width: 14px; height: 14px; margin: 0; border-width: 2px;"></span> Analyzing...';
        btnUploadAnalyze.setAttribute('disabled', 'true');
        btnResetUpload.setAttribute('disabled', 'true');

        const formData = new FormData();
        formData.append('file', selectedFile);

        try {
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Server error occurred during analysis');
            }

            const data = await response.json();
            currentAnalysis = data;
            
            // Reset upload interface and draw outputs
            resetUploadSelection();
            renderAnalysisResult(data);
            displayAlert('File analysis completed successfully.', 'success');

        } catch (err) {
            displayAlert(err.message, 'error');
        } finally {
            btnUploadAnalyze.innerHTML = originalText;
            btnResetUpload.removeAttribute('disabled');
        }
    });

    // ============================================
    // ANALYSIS RESULT RENDERING
    // ============================================
    function renderAnalysisResult(data) {
        analysisResult.style.display = 'block';

        // Update stats
        statTotalPackets.textContent = data.total_packets.toLocaleString();
        statUniqueIps.textContent = data.unique_ips.toLocaleString();
        statThreatCount.textContent = data.threat_count.toLocaleString();

        const statCardThreat = statThreatCount.closest('.stat-card');
        if (data.threat_count > 0) {
            statCardThreat.className = 'stat-card threat-critical';
        } else {
            statCardThreat.className = 'stat-card';
        }

        // Draw threat feed
        renderThreatFeed(data.threats);

        // Draw device tags
        renderDeviceTags(data.devices);

        // Draw protocols distribution
        renderProtocolDistribution(data.protocol_counts, data.total_packets);

        // Draw packets inspector table
        renderPacketsTable(data.packets);

        // Clear search parameters
        packetSearch.value = '';
        protocolFilter.value = 'ALL';
    }

    function renderThreatFeed(threats) {
        if (!threats || threats.length === 0) {
            threatFeedContainer.innerHTML = `
                <div class="empty-state">
                    <p>No suspicious signatures detected inside this capture trace.</p>
                </div>
            `;
            return;
        }

        threatFeedContainer.innerHTML = threats.map(t => `
            <div class="threat-item severity-${t.severity}">
                <div class="threat-meta">
                    <span class="threat-title">${t.type}</span>
                    <span class="threat-details">Source: <strong>${t.source}</strong> | ${t.details}</span>
                </div>
                <span class="threat-badge badge-${t.severity}">${t.severity} (Score: ${t.score})</span>
            </div>
        `).join('');
    }

    function renderDeviceTags(devices) {
        if (!devices || devices.length === 0) {
            deviceTagContainer.innerHTML = '<div class="empty-state"><p>No network nodes resolved.</p></div>';
            return;
        }
        deviceTagContainer.innerHTML = devices.map(ip => `
            <span class="device-tag">${ip}</span>
        `).join('');
    }

    function renderProtocolDistribution(counts, total) {
        if (!counts || Object.keys(counts).length === 0) {
            protocolDistributionContainer.innerHTML = '<div class="empty-state"><p>No network protocols recorded.</p></div>';
            return;
        }

        let html = '';
        for (const [proto, count] of Object.entries(counts)) {
            const pct = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
            html += `
                <div class="proto-bar-row">
                    <div class="proto-bar-info">
                        <span class="proto-bar-name">${proto}</span>
                        <span class="proto-bar-count">${count.toLocaleString()} (${pct}%)</span>
                    </div>
                    <div class="proto-bar-track">
                        <div class="proto-bar-fill ${proto}" style="width: ${pct}%"></div>
                    </div>
                </div>
            `;
        }
        protocolDistributionContainer.innerHTML = html;
    }

    function renderPacketsTable(packets) {
        if (!packets || packets.length === 0) {
            packetTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state" style="text-align: center;">No packets indexed inside database.</td>
                </tr>
            `;
            return;
        }

        packetTableBody.innerHTML = packets.map(p => `
            <tr class="packet-row" data-protocol="${p.protocol}">
                <td>${p.id}</td>
                <td class="packet-ip-mono">${p.src || 'N/A'}</td>
                <td class="packet-ip-mono">${p.dst || 'N/A'}</td>
                <td><span class="packet-proto-badge ${p.protocol}">${p.protocol}</span></td>
                <td>${p.length} bytes</td>
                <td>${p.info}</td>
            </tr>
        `).join('');
    }

    // ============================================
    // CLIENT SIDE SEARCH AND FILTERS (TABLE INSPECTOR)
    // ============================================
    function filterPacketTable() {
        const query = packetSearch.value.toLowerCase();
        const selectedProto = protocolFilter.value;
        const rows = packetTableBody.querySelectorAll('.packet-row');

        rows.forEach(row => {
            const cells = Array.from(row.getElementsByTagName('td'));
            const textMatch = cells.some(td => td.textContent.toLowerCase().includes(query));
            
            const rowProto = row.getAttribute('data-protocol');
            const protoMatch = (selectedProto === 'ALL') || (rowProto === selectedProto);

            if (textMatch && protoMatch) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    packetSearch.addEventListener('input', filterPacketTable);
    protocolFilter.addEventListener('change', filterPacketTable);

    // ============================================
    // LIVE PACKET CAPTURE LOGIC
    // ============================================
    async function toggleLiveCapture(action) {
        if (action === 'start') {
            try {
                const response = await fetch('/live/start', { method: 'POST' });
                if (!response.ok) throw new Error('Failed to start capture agent');

                const data = await response.json();
                if (data.status === 'started') {
                    // GUI updates
                    btnStartSniff.setAttribute('disabled', 'true');
                    btnStopSniff.removeAttribute('disabled');
                    
                    liveStatusDot.className = 'status-dot online';
                    liveStatusText.textContent = 'Live Sniffer Active';
                    
                    if (data.is_mock) {
                        mockWarning.style.display = 'inline-block';
                    } else {
                        mockWarning.style.display = 'none';
                    }

                    // Reset terminal & live threats
                    liveTerminalContainer.innerHTML = '<div class="terminal-line system-msg">SYS: Real-time network stream listener bound successfully. Logs writing...</div>';
                    liveThreatContainer.innerHTML = '';
                    livePacketCounter.textContent = '0';

                    // Start packet poller
                    if (liveSnifferInterval) clearInterval(liveSnifferInterval);
                    liveSnifferInterval = setInterval(fetchLiveUpdate, 1500);
                    displayAlert('Live packet capturing started.', 'success');
                }
            } catch (err) {
                displayAlert(err.message, 'error');
            }
        } else if (action === 'stop') {
            try {
                // Clear interval first
                if (liveSnifferInterval) {
                    clearInterval(liveSnifferInterval);
                    liveSnifferInterval = null;
                }

                const response = await fetch('/live/stop', { method: 'POST' });
                if (!response.ok) throw new Error('Failed to stop capture agent');

                const data = await response.json();
                
                // GUI resets
                btnStartSniff.removeAttribute('disabled');
                btnStopSniff.setAttribute('disabled', 'true');
                
                liveStatusDot.className = 'status-dot offline';
                liveStatusText.textContent = 'Sniffer Inactive';
                mockWarning.style.display = 'none';
                
                if (data.saved) {
                    displayAlert('Live session capture stored in database history.', 'success');
                    // Automatically trigger history list reload
                    loadHistoryLogs();
                } else {
                    displayAlert('Live session capture terminated (no packets captured).', 'success');
                }

            } catch (err) {
                displayAlert(err.message, 'error');
            }
        }
    }

    btnStartSniff.addEventListener('click', () => toggleLiveCapture('start'));
    btnStopSniff.addEventListener('click', () => toggleLiveCapture('stop'));

    async function fetchLiveUpdate() {
        try {
            const response = await fetch('/live/packets');
            if (!response.ok) throw new Error();

            const data = await response.json();
            
            // Check status synchronization
            if (!data.active && liveSnifferInterval) {
                // Server stopped capture on its own
                toggleLiveCapture('stop');
                return;
            }

            // Update live totals
            livePacketCounter.textContent = data.total.toLocaleString();

            if (data.is_mock) {
                mockWarning.style.display = 'inline-block';
            }

            // Output packets into terminal window
            if (data.packets && data.packets.length > 0) {
                // Append only new logs
                // For simplicity, we redraw the log lines of the window
                liveTerminalContainer.innerHTML = data.packets.map(p => `
                    <div class="terminal-line packet">
                        [${new Date().toLocaleTimeString()}] <span class="proto">${p.protocol}</span>: 
                        ${p.src || '?'} <span class="arrow">&rarr;</span> ${p.dst || '?'} 
                        | ${p.length} bytes | ${p.info}
                    </div>
                `).join('');
                
                // Scroll to bottom
                liveTerminalContainer.scrollTop = liveTerminalContainer.scrollHeight;
            }

            // Update live threats
            if (data.threats && data.threats.length > 0) {
                liveThreatContainer.innerHTML = data.threats.map(t => `
                    <div class="threat-item severity-${t.severity}">
                        <div class="threat-meta">
                            <span class="threat-title">${t.type}</span>
                            <span class="threat-details">Source: <strong>${t.source}</strong> | ${t.details}</span>
                        </div>
                        <span class="threat-badge badge-${t.severity}">${t.severity}</span>
                    </div>
                `).join('');
            } else {
                liveThreatContainer.innerHTML = `
                    <div class="empty-state">
                        <p>Scanning network streams... No threat markers detected yet.</p>
                    </div>
                `;
            }

        } catch (err) {
            console.error('Error polling live packets:', err);
        }
    }

    // ============================================
    // USER ANALYSIS HISTORY WORKSPACE
    // ============================================
    async function loadHistoryLogs() {
        try {
            historyTableBody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align: center; padding: 30px;">
                        <span class="spinner" style="width: 20px; height: 20px; display: inline-block;"></span> Loading history...
                    </td>
                </tr>
            `;

            const response = await fetch('/history');
            if (!response.ok) throw new Error('Failed to load past analysis logs');

            const data = await response.json();
            
            if (data.length === 0) {
                historyTableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="empty-state" style="text-align: center; padding: 40px 20px;">
                            No past analyses saved for this profile. Try uploading a PCAP!
                        </td>
                    </tr>
                `;
                return;
            }

            historyTableBody.innerHTML = data.map(item => `
                <tr id="history-row-${item.id}">
                    <td>${item.timestamp}</td>
                    <td style="font-weight: 500;">${item.filename}</td>
                    <td>${item.total_packets.toLocaleString()}</td>
                    <td>
                        <span class="threat-badge badge-${item.threat_count > 0 ? 'Critical' : 'Low'}" style="font-size: 0.65rem;">
                            ${item.threat_count} Alerts
                        </span>
                    </td>
                    <td>${item.unique_ips} IPs</td>
                    <td>
                        <div style="display: flex; gap: 8px;">
                            <button class="btn btn-sm btn-primary btn-load-history" data-id="${item.id}">Load</button>
                            <button class="btn btn-sm btn-danger btn-delete-history" data-id="${item.id}">Delete</button>
                        </div>
                    </td>
                </tr>
            `).join('');

            // Bind actions
            document.querySelectorAll('.btn-load-history').forEach(btn => {
                btn.addEventListener('click', () => loadHistoricalAnalysis(btn.getAttribute('data-id')));
            });

            document.querySelectorAll('.btn-delete-history').forEach(btn => {
                btn.addEventListener('click', () => deleteHistoricalAnalysis(btn.getAttribute('data-id')));
            });

        } catch (err) {
            historyTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state" style="color: var(--color-danger); text-align: center;">
                        Error loading logs: ${err.message}
                    </td>
                </tr>
            `;
        }
    }

    async function loadHistoricalAnalysis(id) {
        try {
            displayAlert('Fetching historical packet record...', 'success');
            const response = await fetch(`/history/${id}`);
            if (!response.ok) throw new Error('Analysis record not found');

            const data = await response.json();
            currentAnalysis = data;

            // Draw results on dashboard
            renderAnalysisResult(data);

            // Auto navigate to Overview Tab
            const overviewMenu = document.querySelector('.menu-item[data-target="overview-tab"]');
            if (overviewMenu) overviewMenu.click();

            displayAlert(`Loaded analysis history: ${data.filename}`, 'success');

        } catch (err) {
            displayAlert(err.message, 'error');
        }
    }

    async function deleteHistoricalAnalysis(id) {
        if (!confirm('Are you sure you want to permanently delete this analysis record?')) {
            return;
        }

        try {
            const response = await fetch(`/history/${id}`, { method: 'DELETE' });
            if (!response.ok) throw new Error('Failed to delete history record');

            // Remove row from HTML
            const row = document.getElementById(`history-row-${id}`);
            if (row) row.remove();
            
            // Check if deleted analysis was the current active one, and clear it
            if (currentAnalysis && currentAnalysis.id == id) {
                analysisResult.style.display = 'none';
                currentAnalysis = null;
            }

            displayAlert('Record deleted successfully.', 'success');

            // If table is empty now, re-trigger full list load
            if (historyTableBody.children.length === 0) {
                loadHistoryLogs();
            }

        } catch (err) {
            displayAlert(err.message, 'error');
        }
    }

    // ============================================
    // EXPORT ACTION HANDLERS
    // ============================================
    btnExportJSON.addEventListener('click', () => {
        if (!currentAnalysis) return;
        
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentAnalysis, null, 4));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `analysis_${currentAnalysis.id || 'export'}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        displayAlert('Analysis exported as JSON.', 'success');
    });

    btnExportCSV.addEventListener('click', () => {
        if (!currentAnalysis || !currentAnalysis.packets) return;

        let csvContent = "data:text/csv;charset=utf-8,";
        // Header
        csvContent += "Packet ID,Source IP,Destination IP,Protocol,Length (bytes),Info\n";
        
        // Rows
        currentAnalysis.packets.forEach(p => {
            const row = [
                p.id,
                p.src || 'N/A',
                p.dst || 'N/A',
                p.protocol || 'Other',
                p.length,
                `"${(p.info || '').replace(/"/g, '""')}"` // Escape double quotes
            ].join(",");
            csvContent += row + "\n";
        });

        const encodedUri = encodeURI(csvContent);
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", encodedUri);
        downloadAnchor.setAttribute("download", `packets_${currentAnalysis.id || 'export'}.csv`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        displayAlert('Analysis exported as CSV.', 'success');
    });
});
