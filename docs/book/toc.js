// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><a href="index.html"><strong aria-hidden="true">1.</strong> Introduction</a></li><li class="chapter-item expanded affix "><li class="part-title">Development Documentation</li><li class="chapter-item expanded "><a href="dev/index.html"><strong aria-hidden="true">2.</strong> Introduction</a></li><li class="chapter-item expanded "><a href="dev/setup.html"><strong aria-hidden="true">3.</strong> Setup Environment</a></li><li class="chapter-item expanded "><a href="dev/clean-code.html"><strong aria-hidden="true">4.</strong> Clean Code Philosophy</a></li><li class="chapter-item expanded "><a href="dev/generate-artifact/generate-artifact.html"><strong aria-hidden="true">5.</strong> Generate Artifact</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="dev/generate-artifact/ami/ami-generate-artifact.html"><strong aria-hidden="true">5.1.</strong> Generate AMI Artifact</a></li><li class="chapter-item expanded "><a href="dev/generate-artifact/ova/ova-generate-artifact.html"><strong aria-hidden="true">5.2.</strong> Generate OVA Artifact</a></li></ol></li><li class="chapter-item expanded "><a href="dev/run-tests/run-tests.html"><strong aria-hidden="true">6.</strong> Run Tests</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="dev/run-tests/ami/ami-run-tests.html"><strong aria-hidden="true">6.1.</strong> Run AMI Tests</a></li><li class="chapter-item expanded "><a href="dev/run-tests/ova/ova-run-tests.html"><strong aria-hidden="true">6.2.</strong> Run OVA Tests</a></li></ol></li><li class="chapter-item expanded "><li class="part-title">Reference Manual</li><li class="chapter-item expanded "><a href="ref/getting-started/introduction.html"><strong aria-hidden="true">7.</strong> Introduction</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/getting-started/ami/ami-introduction.html"><strong aria-hidden="true">7.1.</strong> AMI Introduction</a></li><li class="chapter-item expanded "><a href="ref/getting-started/ova/ova-introduction.html"><strong aria-hidden="true">7.2.</strong> OVA Introduction</a></li></ol></li><li class="chapter-item expanded "><a href="ref/installation/installation.html"><strong aria-hidden="true">8.</strong> Installation</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/installation/ami/ami-installation.html"><strong aria-hidden="true">8.1.</strong> AMI Installation</a></li><li class="chapter-item expanded "><a href="ref/installation/ova/ova-installation.html"><strong aria-hidden="true">8.2.</strong> OVA Installation</a></li></ol></li><li class="chapter-item expanded "><a href="ref/configuration/configuration.html"><strong aria-hidden="true">9.</strong> Configuration</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/configuration/ami/ami-configuration.html"><strong aria-hidden="true">9.1.</strong> AMI Configuration</a></li><li class="chapter-item expanded "><a href="ref/configuration/ova/ova-configuration.html"><strong aria-hidden="true">9.2.</strong> OVA Configuration</a></li></ol></li><li class="chapter-item expanded "><a href="ref/modules/modules.html"><strong aria-hidden="true">10.</strong> Modules</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/modules/provisioner/provisioner.html"><strong aria-hidden="true">10.1.</strong> Provisioner</a></li><li class="chapter-item expanded "><a href="ref/modules/configurer/configurer.html"><strong aria-hidden="true">10.2.</strong> Configurer</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/modules/configurer/core/core.html"><strong aria-hidden="true">10.2.1.</strong> Core Configurer</a></li><li class="chapter-item expanded "><a href="ref/modules/configurer/pre/pre.html"><strong aria-hidden="true">10.2.2.</strong> Pre Configurer</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/modules/configurer/pre/ami/pre-ami.html"><strong aria-hidden="true">10.2.2.1.</strong> AMI Pre Configurer</a></li><li class="chapter-item expanded "><a href="ref/modules/configurer/pre/ova/pre-ova.html"><strong aria-hidden="true">10.2.2.2.</strong> OVA Pre Configurer</a></li></ol></li><li class="chapter-item expanded "><a href="ref/modules/configurer/post/post.html"><strong aria-hidden="true">10.2.3.</strong> Post Configurer</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/modules/configurer/post/ami/post-ami.html"><strong aria-hidden="true">10.2.3.1.</strong> AMI Post Configurer</a></li><li class="chapter-item expanded "><a href="ref/modules/configurer/post/ova/post-ova.html"><strong aria-hidden="true">10.2.3.2.</strong> OVA Post Configurer</a></li></ol></li></ol></li><li class="chapter-item expanded "><a href="ref/modules/test/test.html"><strong aria-hidden="true">10.3.</strong> Test</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/modules/test/ova/ova.html"><strong aria-hidden="true">10.3.1.</strong> Test OVA</a></li><li class="chapter-item expanded "><a href="ref/modules/test/ami/ami.html"><strong aria-hidden="true">10.3.2.</strong> Test AMI</a></li></ol></li></ol></li><li class="chapter-item expanded "><a href="ref/upgrade.html"><strong aria-hidden="true">11.</strong> Upgrade</a></li><li class="chapter-item expanded "><a href="ref/security/security.html"><strong aria-hidden="true">12.</strong> Security</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="ref/security/ami/ami-security.html"><strong aria-hidden="true">12.1.</strong> AMI Security</a></li><li class="chapter-item expanded "><a href="ref/security/ova/ova-security.html"><strong aria-hidden="true">12.2.</strong> OVA Security</a></li></ol></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
