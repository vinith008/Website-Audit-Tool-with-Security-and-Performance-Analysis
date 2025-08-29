document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("url-input");
    const auditBtn = document.getElementById("audit-btn");
    const resultsSection = document.getElementById("results");
    const progressBar = document.getElementById("progressBar");
    const summaryGrid = document.getElementById("summaryGrid");
    const scoreCards = document.getElementById("scoreCards");
    const tabs = document.querySelectorAll(".tab-btn");
    const tabContents = {
        overview: document.getElementById("overview"),
        seo: document.getElementById("seo"),
        performance: document.getElementById("performance"),
        security: document.getElementById("security"),
        accessibility: document.getElementById("accessibility"),
    };
    const overviewValue = document.getElementById("overviewValue");
    const desktopBtn = document.getElementById("desktop-btn");
    const mobileBtn = document.getElementById("mobile-btn");
    const auditMode = document.getElementById("audit-mode");
    const testAgain = document.getElementById("testAgain");
    const exportExcelBtn = document.getElementById("exportExcelBtn");
    const exportPdfBtn = document.getElementById("exportPdfBtn");
    const debugInfo = document.getElementById("debug-info");

    let currentMode = "desktop";
    let socket;
    window.auditData = null;

    // Mode toggle
    desktopBtn.addEventListener("click", () => {
        if (currentMode === "desktop") return;
        currentMode = "desktop";
        desktopBtn.classList.add("active");
        mobileBtn.classList.remove("active");
        auditMode.textContent = "Mode: desktop";
        console.log("Switched to desktop mode");
    });

    mobileBtn.addEventListener("click", () => {
        if (currentMode === "mobile") return;
        currentMode = "mobile";
        mobileBtn.classList.add("active");
        desktopBtn.classList.remove("active");
        auditMode.textContent = "Mode: mobile";
        console.log("Switched to mobile mode");
    });

    // Socket setup with fallback
    try {
        socket = io();
        socket.on("connect", () => {
            console.log("Connected to SocketIO");
            debugInfo.textContent = "SocketIO Connected";
        });
        socket.on("connect_error", (error) => {
            console.error("SocketIO connection error:", error);
            debugInfo.textContent = "SocketIO Error: Fallback to HTTP";
            socket = null;
        });
        socket.on("audit_progress", (data) => {
            progressBar.style.width = `${data.progress}%`;
            progressBar.textContent = `${data.progress}% ${getProgressSymbol(data.progress)} - ${data.message || "Processing..."}`;
            console.log(`Progress: ${data.progress}% - ${data.message}`);
            debugInfo.textContent = `Progress: ${data.progress}% - ${data.message}`;
        });
        socket.on("audit_complete", (payload) => {
            console.log("Audit complete received:", payload);
            handleAuditComplete(payload);
        });
        socket.on("audit_error", (err) => {
            console.error("Audit error:", err);
            alert("Audit failed: " + (err.message || "Unknown error"));
            resetUI();
            debugInfo.textContent = `Audit Error: ${err.message || "Unknown"}`;
        });
    } catch (e) {
        console.error("SocketIO setup failed:", e);
        debugInfo.textContent = "SocketIO Setup Failed: Using HTTP";
        socket = null;
    }

    // Tab navigation
    tabs.forEach((tab) => {
        tab.addEventListener("click", () => {
            tabs.forEach((t) => t.classList.remove("active"));
            tab.classList.add("active");
            Object.values(tabContents).forEach((content) => (content.style.display = "none"));
            tabContents[tab.dataset.tab].style.display = "block";
        });
    });

    // Audit button
    auditBtn.addEventListener("click", () => {
        console.log("Audit button clicked, mode:", currentMode);
        const url = urlInput.value.trim();
        if (!url) {
            urlInput.style.borderColor = "#ef5350";
            setTimeout(() => (urlInput.style.borderColor = ""), 500);
            alert("Please enter a URL");
            return;
        }
        auditBtn.disabled = true;
        debugInfo.textContent = "Starting Audit...";

        resultsSection.style.display = "block";
        resultsSection.classList.add("slide-in");
        progressBar.style.width = "5%";
        progressBar.textContent = "5% ⏳ - Initializing audit...";

        startAudit(url);
    });

    // Test Again button
    testAgain.addEventListener("click", () => {
        location.reload();
    });

    // Export Excel button
    exportExcelBtn.addEventListener("click", () => {
        if (!window.auditData) return alert("No audit data available");
        const wb = XLSX.utils.book_new();
        const wsData = [["Category", "Score", "Issues"]];
        ["performance", "seo", "security", "accessibility"].forEach((cat) => {
            const data = window.auditData[cat] || {};
            wsData.push([cat.charAt(0).toUpperCase() + cat.slice(1), data.score || 0, (data.issues || []).join("; ")]);
        });
        const ws = XLSX.utils.aoa_to_sheet(wsData);
        XLSX.utils.book_append_sheet(wb, ws, "Audit Report");
        XLSX.writeFile(wb, "audit_report.xlsx");
    });

    // Export PDF button
    exportPdfBtn.addEventListener("click", () => {
        if (!window.auditData) return alert("No audit data available");
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        doc.setFontSize(18);
        doc.text("WebPulse 360 Audit Report", 10, 15);
        let y = 25;
        doc.setFontSize(12);
        ["performance", "seo", "security", "accessibility"].forEach((cat) => {
            const data = window.auditData[cat] || {};
            doc.text(`${cat.charAt(0).toUpperCase() + cat.slice(1)} Score: ${data.score || 0}`, 10, y);
            y += 10;
            if (data.issues && data.issues.length) {
                doc.text("Issues:", 10, y);
                y += 10;
                data.issues.forEach((i) => {
                    doc.text(`- ${i}`, 15, y);
                    y += 7;
                });
            } else {
                doc.text("No issues", 10, y);
                y += 10;
            }
            y += 5;
        });
        doc.save("audit_report.pdf");
    });

    function startAudit(url) {
        const payload = { url, mode: currentMode };
        console.log("Starting audit with payload:", payload);
        const timeout = setTimeout(() => {
            alert("Audit timed out. Please try again.");
            resetUI();
        }, 30000); // 30 seconds timeout
        if (socket) {
            socket.emit("start_audit", payload, () => clearTimeout(timeout));
        } else {
            fetch("/audit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            })
                .then((res) => res.json())
                .then((data) => {
                    clearTimeout(timeout);
                    handleAuditComplete(data);
                })
                .catch((err) => {
                    clearTimeout(timeout);
                    console.error("HTTP audit error:", err);
                    alert("Audit failed");
                    resetUI();
                });
        }
    }

    function handleAuditComplete(payload) {
        if (payload.error) {
            alert("Audit failed: " + payload.error);
            resetUI();
            return;
        }
        window.auditData = payload;
        const overall = payload.overall || {};
        const performance = payload.performance || {};
        const seo = payload.seo || {};
        const security = payload.security || {};
        const accessibility = payload.accessibility || {};

        progressBar.style.width = "100%";
        progressBar.textContent = "100% ✅ - Audit complete!";

        summaryGrid.innerHTML = `
            <div class="summary-card"><strong>Overall Score:</strong> ${overall.score || "N/A"}%</div>
            <div class="summary-card"><strong>Response Time:</strong> ${overall.response_time || "N/A"} ms</div>
            <div class="summary-card"><strong>Pages Scanned:</strong> ${overall.pages_scanned || "N/A"}</div>
            <div class="summary-card"><strong>Audit Duration:</strong> ${overall.audit_duration || "N/A"} sec</div>
            <div class="summary-card"><strong>Uptime:</strong> ${overall.uptime || "N/A"}%</div>
            <div class="summary-card"><strong>Error Rate:</strong> ${overall.error_rate || "N/A"}%</div>
        `;
        scoreCards.innerHTML = `
            <div class="score-card">Performance: <div class="progress-bar" style="width:${Math.min(performance.score || 0, 100)}%;">${performance.score || "N/A"}%</div></div>
            <div class="score-card">SEO: <div class="progress-bar" style="width:${Math.min(seo.score || 0, 100)}%;">${seo.score || "N/A"}%</div></div>
            <div class="score-card">Security: <div class="progress-bar" style="width:${Math.min(security.score || 0, 100)}%;">${security.score || "N/A"}%</div></div>
            <div class="score-card">Accessibility: <div class="progress-bar" style="width:${Math.min(accessibility.score || 0, 100)}%;">${accessibility.score || "N/A"}%</div></div>
        `;

        overviewValue.innerHTML = `
            <h3>Overall Summary</h3>
            <p>Overall Score: <div class="progress-bar" style="width:${Math.min(overall.score || 0, 100)}%;">${overall.score || "N/A"}%</div></p>
            <p>Response Time: ${overall.response_time || "N/A"} ms</p>
            <p>Total Pages Scanned: ${overall.pages_scanned || 0}</p>
            <p>Audit Duration: ${overall.audit_duration || "N/A"} sec</p>
            <p>Uptime: ${overall.uptime || "N/A"}%</p>
            <p>Error Rate: ${overall.error_rate || "N/A"}%</p>
        `;

        tabContents.seo.innerHTML = `
            <h3>SEO ⏳</h3>
            <p>Title: ${seo.title || "None"}</p>
            <p>Score: <div class="progress-bar" style="width:${Math.min(seo.score || 0, 100)}%;">${seo.score || "N/A"}%</div></p>
            <p>Meta Description Length: ${seo.meta_desc_length || "N/A"} chars</p>
            <p>Keyword Density: ${seo.keyword_density || "N/A"}%</p>
            <p>Backlinks: ${seo.backlinks || "N/A"}</p>
            <p>Page Depth: ${seo.page_depth || "N/A"}</p>
            <p>Internal Links: ${seo.internal_links || "N/A"}</p>
            <ul>${(seo.issues || []).map((i) => `<li>${i}</li>`).join("") || "<li>No issues ✅</li>"}</ul>
        `;
        tabContents.security.innerHTML = `
            <h3>Security 🔒</h3>
            <p>SSL: ${security.ssl_valid ? "✅ Secure" : "❌ Not Secure"}</p>
            <p>Score: <div class="progress-bar" style="width:${Math.min(security.score || 0, 100)}%;">${security.score || "N/A"}%</div></p>
            <p>Encryption Strength: ${security.encryption_strength || "N/A"} bits</p>
            <p>Security Headers: ${security.security_headers || "N/A"}</p>
            <p>Vulnerabilities Found: ${security.vulnerabilities || 0} ⚠️</p>
            <p>Certificate Expiry: ${security.certificate_expiry || "N/A"} days</p>
            <p>Mixed Content: ${security.mixed_content ? "Yes ⚠️" : "No ✅"}</p>
            <ul>${(security.issues || []).map((i) => `<li>${i}</li>`).join("") || "<li>No issues ✅</li>"}</ul>
        `;
        tabContents.accessibility.innerHTML = `
            <h3>Accessibility ♿</h3>
            <p>Score: <div class="progress-bar" style="width:${Math.min(accessibility.score || 0, 100)}%;">${accessibility.score || "N/A"}%</div></p>
            <p>Contrast Ratio: ${accessibility.contrast_ratio || "N/A"}</p>
            <p>Alt Text Coverage: ${accessibility.alt_text_coverage || "N/A"}%</p>
            <p>Keyboard Navigation: ${accessibility.keyboard_nav || "N/A"}</p>
            <p>Screen Reader Compatibility: ${accessibility.screen_reader || "N/A"}</p>
            <p>Color Blind Compatibility: ${accessibility.color_blind_compatibility || "N/A"}</p>
            <p>ARIA Usage: ${accessibility.aria_usage || "N/A"}%</p>
            <ul>${(accessibility.issues || []).map((i) => `<li>${i}</li>`).join("") || "<li>No issues ✅</li>"}</ul>
        `;
        tabContents.performance.innerHTML = `
            <h3>Performance ⚡</h3>
            <p>Score: <div class="progress-bar" style="width:${Math.min(performance.score || 0, 100)}%;">${performance.score || "N/A"}%</div></p>
            <p>Largest Contentful Paint: ${performance.lcp_s || "N/A"} s <div class="progress-bar" style="width:${Math.min((2.5 - (performance.lcp_s || 0)) / 2.5 * 100, 100)}%;">${performance.lcp_s || "N/A"} s</div></p>
            <p>First Contentful Paint: ${performance.fcp_s || "N/A"} s <div class="progress-bar" style="width:${Math.min((1.8 - (performance.fcp_s || 0)) / 1.8 * 100, 100)}%;">${performance.fcp_s || "N/A"} s</div></p>
            <p>Cumulative Layout Shift: ${performance.cls || "N/A"} <div class="progress-bar" style="width:${Math.min((0.1 - (performance.cls || 0)) / 0.1 * 100, 100)}%;">${performance.cls || "N/A"}</div></p>
            <p>Time to Interactive: ${performance.tti || "N/A"} s <div class="progress-bar" style="width:${Math.min((3.8 - (performance.tti || 0)) / 3.8 * 100, 100)}%;">${performance.tti || "N/A"} s</div></p>
            <p>First Input Delay: ${performance.fid || "N/A"} ms <div class="progress-bar" style="width:${Math.min((100 - (performance.fid || 0)) / 100 * 100, 100)}%;">${performance.fid || "N/A"} ms</div></p>
            <p>Page Size: ${performance.page_size || "N/A"} KB <div class="progress-bar" style="width:${Math.min((2000 - (performance.page_size || 0)) / 2000 * 100, 100)}%;">${performance.page_size || "N/A"} KB</div></p>
            <p>Requests Count: ${performance.requests_count || "N/A"} <div class="progress-bar" style="width:${Math.min((50 - (performance.requests_count || 0)) / 50 * 100, 100)}%;">${performance.requests_count || "N/A"}</div></p>
        `;

        tabs[0].click();
        auditBtn.disabled = false;
        debugInfo.textContent = "Audit Completed Successfully - Results Displayed";
        console.log("Results rendered successfully");
    }

    function resetUI() {
        progressBar.style.width = "0%";
        progressBar.textContent = "";
        auditBtn.disabled = false;
        resultsSection.classList.remove("slide-in");
        resultsSection.style.display = "none";
        overviewValue.innerHTML = "";
        window.auditData = null;
        debugInfo.textContent = "Ready for New Audit";
    }

    function getProgressSymbol(progress) {
        return progress < 100 ? "⏳" : "✅";
    }
});