document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const scanBtn = document.getElementById('scanBtn');
    const progressSection = document.getElementById('progressSection');
    const resultsSection = document.getElementById('resultsSection');
    const emptyState = document.getElementById('emptyState');
    const resultsContent = document.getElementById('resultsContent');
    const waybackOptions = document.getElementById('waybackOptions');
    const cookiesGroup = document.getElementById('cookiesGroup');
    const keywordLabel = document.getElementById('keywordLabel');
    const authorizationGroup = document.getElementById('authorizationGroup');
    const authorizedCheckbox = document.getElementById('authorized');
    const apiTokenInput = document.getElementById('apiToken');

    let currentMatches = [];
    let currentParams = null;
    let activeController = null;

    function authHeaders(extra = {}) {
        const token = apiTokenInput ? apiTokenInput.value.trim() : '';
        return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
    }

    function setBusy(isBusy) {
        scanBtn.disabled = isBusy;
        document.getElementById('btnText').classList.toggle('hidden', isBusy);
        document.getElementById('btnLoader').classList.toggle('hidden', !isBusy);
    }

    async function responseError(response) {
        if (response.status === 401) {
            return 'Unauthorized: provide a valid API token.';
        }
        if (response.status === 429) {
            return 'Rate limit exceeded. Try again later.';
        }
        try {
            const data = await response.json();
            return data.error || `Request failed (${response.status})`;
        } catch {
            return `Request failed (${response.status})`;
        }
    }

    function dispatchScanEvent(data) {
        if (data.type === 'progress') {
            updateProgress(data);
        } else if (data.type === 'match') {
            currentMatches.push(data.match);
            addMatchToUI(data.match);
            showResultsSection();
        } else if (data.type === 'complete') {
            completeScan(data.message);
            return true;
        } else if (data.type === 'error') {
            handleError(data.error || 'Scan failed.');
            return true;
        }
        return false;
    }

    async function streamScan(params) {
        activeController = new AbortController();
        let response;
        try {
            response = await fetch(`/api/scan?${params}`, {
                headers: authHeaders(),
                signal: activeController.signal
            });
        } catch (error) {
            if (error.name !== 'AbortError') {
                handleError('Failed to start scan: ' + error.message);
            }
            return;
        }

        if (!response.ok) {
            handleError(await responseError(response));
            return;
        }
        if (!response.body) {
            handleError('Streaming is not supported by this browser.');
            return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let finished = false;

        try {
            while (!finished) {
                const { value, done } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });

                let boundary;
                while ((boundary = buffer.indexOf('\n\n')) >= 0) {
                    const event = buffer.slice(0, boundary);
                    buffer = buffer.slice(boundary + 2);
                    for (const line of event.split('\n')) {
                        if (!line.startsWith('data: ')) continue;
                        try {
                            const data = JSON.parse(line.slice(6));
                            if (dispatchScanEvent(data)) {
                                finished = true;
                                break;
                            }
                        } catch {
                            // Ignore malformed SSE frames rather than crashing the UI.
                        }
                    }
                    if (finished) break;
                }
            }
        } catch (error) {
            if (error.name !== 'AbortError') {
                handleError('Lost connection to server.');
            }
        } finally {
            if (finished) {
                try {
                    await reader.cancel();
                } catch {
                    // The stream may already be closed.
                }
            }
            activeController = null;
        }
    }

    // Mode Toggle Logic
    document.querySelectorAll('input[name="scanMode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'live') {
                waybackOptions.style.display = 'none';
                cookiesGroup.style.display = 'block';
                authorizationGroup.style.display = 'flex';
                keywordLabel.textContent = 'Flag Pattern (e.g. ctf)';
                document.getElementById('keyword').placeholder = 'ctf';
            } else {
                waybackOptions.style.display = 'block';
                cookiesGroup.style.display = 'none';
                authorizationGroup.style.display = 'none';
                keywordLabel.textContent = 'Search Pattern / Keyword';
                document.getElementById('keyword').placeholder = 'password, API_KEY or ctf{...';
            }
        });
    });

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const domain = document.getElementById('domain').value.trim();
        const keyword = document.getElementById('keyword').value.trim();
        const mode = document.querySelector('input[name="scanMode"]:checked').value;

        if (!domain) {
            alert('Please fill in the domain field');
            return;
        }

        if (mode === 'live' && !authorizedCheckbox.checked) {
            alert('Confirm that you are authorized to test this target before running a live scan.');
            return;
        }

        // Reset UI
        setBusy(true);
        progressSection.style.display = 'none';
        resultsSection.style.display = 'none';
        emptyState.style.display = 'none';
        resultsContent.innerHTML = '';

        if (mode === 'live') {
            const cookies = document.getElementById('cookies').value.trim();
            const useRegex = document.getElementById('useRegex').checked;
            try {
                const response = await fetch('/api/live-scan', {
                    method: 'POST',
                    headers: authHeaders({ 'Content-Type': 'application/json' }),
                    body: JSON.stringify({
                        url: domain,
                        flag_pattern: keyword,
                        cookies: cookies,
                        use_regex: useRegex,
                        authorized: true
                    })
                });

                if (!response.ok) {
                    throw new Error(await responseError(response));
                }
                renderLiveResults(await response.json());
            } catch (error) {
                handleError(error.message);
            } finally {
                setBusy(false);
            }
            return;
        }

        // Wayback Mode Logic
        const year = document.getElementById('year').value.trim() || undefined;
        const limit = parseInt(document.getElementById('limit').value) || 100;
        const useRegex = document.getElementById('useRegex').checked;

        currentParams = { domain, keyword, year, limit, useRegex };
        currentMatches = [];

        progressSection.style.display = 'block';

        const params = new URLSearchParams({
            domain,
            keyword,
            limit: limit.toString(),
            use_regex: useRegex.toString(),
            ...(year && { year })
        });

        await streamScan(params);
    });

    function updateProgress(data) {
        document.getElementById('progressMessage').textContent = data.message || '';

        if (data.totalSnapshots > 0) {
            const percentage = (data.currentSnapshot / data.totalSnapshots) * 100;
            document.getElementById('progressFill').style.width = percentage + '%';
            document.getElementById('progressCount').textContent =
                `${data.currentSnapshot} / ${data.totalSnapshots}`;
        }
    }

    function showResultsSection() {
        resultsSection.style.display = 'block';
        emptyState.style.display = 'none';
    }

    function addMatchToUI(match) {
        const matchCard = document.createElement('div');
        matchCard.className = 'match-card';

        matchCard.innerHTML = `
            <div class="match-header">
                <span class="match-timestamp">Snapshot: ${escapeHtml(String(match.timestamp || ''))}</span>
                <span class="match-type">${escapeHtml(String(match.matchType || ''))}</span>
            </div>
            <div class="match-snippet">${escapeHtml(match.snippet)}</div>
            <div class="match-url">
                <a href="${escapeHtml(match.archiveUrl)}" target="_blank" rel="noopener noreferrer">View Archive</a>
            </div>
        `;

        resultsContent.appendChild(matchCard);
    }

    function completeScan(message) {
        setBusy(false);
        progressSection.style.display = 'none';
        activeController = null;

        if (currentMatches.length === 0) {
            resultsSection.style.display = 'none';
            emptyState.style.display = 'flex';
            emptyState.innerHTML = `
                <div class="empty-message">
                    <p>Scan Complete</p>
                    <p style="color: var(--text-secondary); margin-top: 10px;">${escapeHtml(message || 'No matches found.')}</p>
                </div>
            `;
        } else {
            showResultsSection();
        }
    }

    function handleError(message) {
        setBusy(false);
        progressSection.style.display = 'none';
        resultsSection.style.display = 'none';
        emptyState.style.display = 'flex';
        emptyState.innerHTML = `
            <div class="empty-message" style="color: #ff4444;">
                <p>ERROR</p>
                <p style="color: var(--text-secondary); margin-top: 10px;">${escapeHtml(message || 'Unknown error')}</p>
            </div>
        `;

        if (activeController) {
            activeController.abort();
            activeController = null;
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Download Report
    document.getElementById('downloadBtn').addEventListener('click', () => {
        if (!currentParams || currentMatches.length === 0) return;

        let report = 'WEBWAY09 ARCHIVED CONTENT SCAN REPORT\n';
        report += '============================\n\n';
        report += `Target Domain: ${currentParams.domain}\n`;
        report += `Search Keyword: ${currentParams.keyword}\n`;
        if (currentParams.year) {
            report += `Year Filter: ${currentParams.year}\n`;
        }
        report += `Scan Date: ${new Date().toISOString()}\n`;
        report += `Total Matches: ${currentMatches.length}\n\n`;
        report += 'FINDINGS\n';
        report += '========\n\n';

        currentMatches.forEach((match, index) => {
            report += `[${index + 1}] MATCH FOUND in Snapshot ${match.timestamp}\n`;
            report += `    URL: ${match.archiveUrl}\n`;
            report += `    Type: Found in ${match.matchType}\n`;
            report += `    Snippet: ${match.snippet}\n\n`;
        });

        // Download the file
        const blob = new Blob([report], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `wayback-report-${new Date().getTime()}.txt`;
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(url);
        a.remove();
    });

    function renderLiveResults(data) {
        if (data.error) {
            handleError(data.error, null);
            return;
        }

        showResultsSection();

        // 1. Headers
        if (data.headers && Object.keys(data.headers).length > 0) {
            const section = document.createElement('div');
            section.className = 'match-card';
            section.innerHTML = `
                <div class="match-header" style="border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 10px;">
                    <span class="match-type" style="color: #00e5ff;">INTERESTING HEADERS</span>
                </div>
                <div style="font-family: monospace; font-size: 0.9em;">
                    ${Object.entries(data.headers).map(([k, v]) => `
                        <div style="margin-bottom: 5px;">
                            <span style="color: #888;">${escapeHtml(k)}:</span> 
                            <span style="color: #fff;">${escapeHtml(v)}</span>
                        </div>
                    `).join('')}
                </div>
            `;
            resultsContent.appendChild(section);
        }

        // 2. Flags
        if (data.flags && data.flags.length > 0) {
            const section = document.createElement('div');
            section.className = 'match-card';
            section.innerHTML = `
                <div class="match-header" style="border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 10px;">
                    <span class="match-type" style="color: #ff0055;">FLAGS FOUND</span>
                </div>
                <div style="font-family: monospace;">
                    ${data.flags.map(f => `<div style="color: #ff0055; font-weight: bold;">[+] ${escapeHtml(f)}</div>`).join('')}
                </div>
            `;
            resultsContent.appendChild(section);
        }

        // 6. Robots.txt
        if (data.robots_txt || data.robots_status) {
            const section = document.createElement('div');
            section.className = 'match-card';

            let statusColor = '#888';
            if (data.robots_status === 200) statusColor = '#00ff41';
            else if (data.robots_status === 404) statusColor = '#ffaa00';
            else statusColor = '#ff4444';

            section.innerHTML = `
            <div class="match-header" style="border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 10px;">
                <span class="match-type" style="color: #ffffff;">ROBOTS.TXT</span>
                <span style="float: right; color: ${statusColor}; font-family: monospace;">[${data.robots_status || 'UNKNOWN'}]</span>
            </div>
            ${data.robots_txt ?
                    `<div style="font-family: monospace; font-size: 0.9em; white-space: pre-wrap; color: #aaa; max-height: 300px; overflow-y: auto;">${escapeHtml(data.robots_txt)}</div>` :
                    `<div style="color: #666; font-style: italic;">No content retrieved.</div>`
                }
        `;
            resultsContent.appendChild(section);
        }

        // 3. Comments
        if (data.comments && data.comments.length > 0) {
            const section = document.createElement('div');
            section.className = 'match-card';
            section.innerHTML = `
                <div class="match-header" style="border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 10px;">
                    <span class="match-type" style="color: #ffaa00;">HTML COMMENTS</span>
                </div>
                <div style="font-family: monospace; font-size: 0.9em; color: #888;">
                    ${data.comments.map(c => `<div style="margin-bottom: 10px; border-left: 2px solid #333; padding-left: 10px;">${escapeHtml(c)}</div>`).join('')}
                </div>
            `;
            resultsContent.appendChild(section);
        }

        // 4. Scripts & Images (Summary)
        if ((data.scripts && data.scripts.length > 0) || (data.images && data.images.length > 0)) {
            const section = document.createElement('div');
            section.className = 'match-card';
            section.innerHTML = `
                <div class="match-header" style="border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 10px;">
                    <span class="match-type" style="color: #00ff41;">ASSETS FOUND</span>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <h4 style="color: #888; margin-bottom: 10px;">Scripts (${data.scripts.length})</h4>
                        <div style="max-height: 200px; overflow-y: auto; font-size: 0.85em;">
                            ${data.scripts.map(s => `<div style="margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(s)}</div>`).join('')}
                        </div>
                    </div>
                    <div>
                        <h4 style="color: #888; margin-bottom: 10px;">Images (${data.images.length})</h4>
                        <div style="max-height: 200px; overflow-y: auto; font-size: 0.85em;">
                            ${data.images.map(i => `<div style="margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(i)}</div>`).join('')}
                        </div>
                    </div>
                </div>
            `;
            resultsContent.appendChild(section);
        }

        // 5. Deep Analysis Findings
        if (data.deep_results && data.deep_results.length > 0) {
            const section = document.createElement('div');
            section.className = 'match-card';
            section.innerHTML = `
                <div class="match-header" style="border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 10px;">
                    <span class="match-type" style="color: #ff00ff;">DEEP ANALYSIS FINDINGS</span>
                </div>
                <div style="font-family: monospace; font-size: 0.9em;">
                    ${data.deep_results.map(res => `
                        <div style="margin-bottom: 15px; border: 1px solid #333; padding: 10px; border-radius: 4px;">
                            <div style="color: #00e5ff; margin-bottom: 5px; word-break: break-all;">
                                <a href="${escapeHtml(res.url)}" target="_blank" rel="noopener noreferrer" style="color: #00e5ff; text-decoration: none;">${escapeHtml(res.url)}</a>
                            </div>
                            
                            ${res.flags && res.flags.length > 0 ? `
                                <div style="margin-top: 5px;">
                                    <div style="color: #ff0055; font-weight: bold;">FLAGS:</div>
                                    ${res.flags.map(f => `<div style="padding-left: 10px;">${escapeHtml(f)}</div>`).join('')}
                                </div>
                            ` : ''}

                            ${res.secrets && res.secrets.length > 0 ? `
                                <div style="margin-top: 5px;">
                                    <div style="color: #ff4444; font-weight: bold;">SECRETS FOUND:</div>
                                    ${res.secrets.map(s => `<div style="padding-left: 10px; color: #ff9999;">${escapeHtml(s)}</div>`).join('')}
                                </div>
                            ` : ''}

                            ${res.endpoints && res.endpoints.length > 0 ? `
                                <div style="margin-top: 5px;">
                                    <div style="color: #00ff41; font-weight: bold;">ENDPOINTS:</div>
                                    <div style="color: #88ffaa; max-height: 100px; overflow-y: auto;">
                                        ${res.endpoints.map(e => `<div style="padding-left: 10px;">${escapeHtml(e)}</div>`).join('')}
                                    </div>
                                </div>
                            ` : ''}
                            
                            ${res.comments && res.comments.length > 0 ? `
                                <div style="margin-top: 5px;">
                                    <div style="color: #ffaa00; font-weight: bold;">COMMENTS:</div>
                                    <div style="color: #888; max-height: 100px; overflow-y: auto;">
                                        ${res.comments.map(c => `<div style="padding-left: 10px; white-space: pre-wrap;">${escapeHtml(c)}</div>`).join('')}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    `).join('')}
                </div>
            `;
            resultsContent.appendChild(section);
        }

        if (resultsContent.children.length === 0) {
            emptyState.style.display = 'flex';
            emptyState.innerHTML = `
                <div class="empty-message">
                    <p>No interesting data found.</p>
                </div>
            `;
            resultsSection.style.display = 'none';
        }
    }

    // --- Resizable Sidebar Logic ---
    const resizer = document.getElementById('resizer');
    const grid = document.querySelector('.grid');
    let isResizing = false;

    if (resizer && grid) {
        resizer.addEventListener('mousedown', (e) => {
            isResizing = true;
            resizer.classList.add('resizing');
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
        });

        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;

            // Calculate new width relative to the container
            const containerRect = grid.getBoundingClientRect();
            let newWidth = e.clientX - containerRect.left;

            // Min/Max constraints
            if (newWidth < 300) newWidth = 300;
            if (newWidth > containerRect.width - 400) newWidth = containerRect.width - 400;

            grid.style.setProperty('--left-width', `${newWidth}px`);
        });

        document.addEventListener('mouseup', () => {
            if (isResizing) {
                isResizing = false;
                resizer.classList.remove('resizing');
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
            }
        });
    }

});
