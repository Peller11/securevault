// Minimal client-side behavior. Deliberately dependency-free and loaded
// as an external file (not inline) so it complies with the app's strict
// Content-Security-Policy (script-src 'self', no inline scripts or
// inline event handler attributes).

document.addEventListener("DOMContentLoaded", () => {
    initFlashDismiss();
    initSidebarDrawer();
    initDropdown("userMenuTrigger", "userMenuDropdown");
    initDropdown("notifTrigger", "notifDropdown");
    initTabs();
    initDeleteConfirm();
    initTableSearch();
    initFilterChips();
});

function initFlashDismiss() {
    document.querySelectorAll(".flash").forEach((el) => {
        setTimeout(() => {
            el.style.transition = "opacity 0.4s ease";
            el.style.opacity = "0";
            setTimeout(() => el.remove(), 400);
        }, 5000);
    });
}

function initSidebarDrawer() {
    const sidebar = document.getElementById("sidebar");
    const toggle = document.getElementById("menuToggle");
    const backdrop = document.getElementById("sidebarBackdrop");
    if (!sidebar || !toggle || !backdrop) return;

    const open = () => { sidebar.classList.add("open"); backdrop.classList.add("open"); };
    const close = () => { sidebar.classList.remove("open"); backdrop.classList.remove("open"); };

    toggle.addEventListener("click", () => {
        sidebar.classList.contains("open") ? close() : open();
    });
    backdrop.addEventListener("click", close);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
}

// Generic dropdown wiring: a trigger button toggles a panel, closes on
// outside click or Escape, and closing one dropdown closes any others.
function initDropdown(triggerId, panelId) {
    const trigger = document.getElementById(triggerId);
    const panel = document.getElementById(panelId);
    if (!trigger || !panel) return;

    trigger.addEventListener("click", (e) => {
        e.stopPropagation();
        const willOpen = !panel.classList.contains("open");
        document.querySelectorAll(".dropdown-panel.open").forEach((p) => p.classList.remove("open"));
        if (willOpen) panel.classList.add("open");
    });
    document.addEventListener("click", () => panel.classList.remove("open"));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") panel.classList.remove("open"); });
}

function initTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    if (!tabButtons.length) return;

    tabButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const target = btn.getAttribute("data-tab");
            tabButtons.forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            document.querySelectorAll(".tab-panel").forEach((panel) => {
                panel.classList.toggle("active", panel.id === "tab-" + target);
            });
        });
    });
}

function initDeleteConfirm() {
    const backdrop = document.getElementById("confirmModalBackdrop");
    if (!backdrop) return;
    const messageEl = document.getElementById("confirmModalMessage");
    const confirmBtn = document.getElementById("confirmModalConfirm");
    const cancelBtn = document.getElementById("confirmModalCancel");
    let pendingForm = null;

    document.querySelectorAll(".delete-trigger").forEach((trigger) => {
        trigger.addEventListener("click", () => {
            pendingForm = trigger.closest("form");
            const label = trigger.getAttribute("data-confirm-label") || "this item";
            messageEl.textContent = `This will permanently delete "${label}". This action cannot be undone.`;
            backdrop.classList.add("open");
        });
    });

    const close = () => { backdrop.classList.remove("open"); pendingForm = null; };

    confirmBtn.addEventListener("click", () => {
        if (pendingForm) pendingForm.submit();
        close();
    });
    cancelBtn.addEventListener("click", close);
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
}

// Real, working client-side filtering: if the current page has a table
// marked [data-searchable-table], typing in the topbar search (or a local
// filter field) hides rows whose text doesn't match. No-op on pages
// without such a table, so the search field never pretends to search
// something it doesn't.
function initTableSearch() {
    const inputs = document.querySelectorAll("[data-search-input]");
    const table = document.querySelector("[data-searchable-table]");
    if (!inputs.length || !table) return;

    const rows = () => table.querySelectorAll("tbody tr");

    inputs.forEach((input) => {
        input.addEventListener("input", () => {
            const query = input.value.trim().toLowerCase();
            rows().forEach((row) => {
                const matches = !query || row.textContent.toLowerCase().includes(query);
                row.style.display = matches ? "" : "none";
            });
        });
    });
}

// Filter chips (e.g. file-type filters on My Files) toggle a data-type
// match against [data-searchable-table] rows' data-file-type attribute.
function initFilterChips() {
    const chips = document.querySelectorAll(".filter-chip");
    const table = document.querySelector("[data-searchable-table]");
    if (!chips.length || !table) return;

    chips.forEach((chip) => {
        chip.addEventListener("click", () => {
            chips.forEach((c) => c.classList.remove("active"));
            chip.classList.add("active");
            const filter = chip.getAttribute("data-filter");
            table.querySelectorAll("tbody tr").forEach((row) => {
                const matches = filter === "all" || row.getAttribute("data-file-type") === filter;
                row.style.display = matches ? "" : "none";
            });
        });
    });
}
