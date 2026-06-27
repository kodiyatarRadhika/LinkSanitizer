// --- Theme Controller Script ---
const themeToggle = document.getElementById('themeToggle');
const currentTheme = localStorage.getItem('theme') || 'light';

if (currentTheme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
    themeToggle.innerText = "☀️ Light Mode";
}

themeToggle.addEventListener('click', () => {
    let theme = document.documentElement.getAttribute('data-theme');
    if (theme === 'dark') {
        document.documentElement.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
        themeToggle.innerText = "🌙 Dark Mode";
    } else {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
        themeToggle.innerText = "☀️ Light Mode";
    }
});

// --- Navigation Controller Elements ---
const urlTabBtn = document.getElementById('urlTabBtn');
const qrTabBtn = document.getElementById('qrTabBtn');
const urlForm = document.getElementById('urlForm');
const qrForm = document.getElementById('qrForm');
const resultDiv = document.getElementById('result');

urlTabBtn.addEventListener('click', () => {
    urlTabBtn.classList.add('active');
    qrTabBtn.classList.remove('active');
    urlForm.classList.remove('hidden');
    qrForm.classList.add('hidden');
    resultDiv.style.display = 'none';
});

qrTabBtn.addEventListener('click', () => {
    qrTabBtn.classList.add('active');
    urlTabBtn.classList.remove('active');
    qrForm.classList.remove('hidden');
    urlForm.classList.add('hidden');
    resultDiv.style.display = 'none';
});

// --- Core Threats Parsing Heuristic Engine ---
function inspectUrlPathAndDomain(urlObject) {
    const domain = urlObject.hostname.toLowerCase();
    const pathname = urlObject.pathname.toLowerCase();
    let findings = [];

    const commonBrands = ['google', 'microsoft', 'apple', 'amazon', 'netflix', 'paypal', 'facebook', 'github'];
    for (let i = 0; i < commonBrands.length; i++) {
        const brand = commonBrands[i];
        if (domain.includes(brand)) {
            const isOfficial = domain.endsWith(brand + '.com') || 
                               domain.endsWith(brand + '.org') || 
                               domain.endsWith(brand + '.net') ||
                               domain.endsWith('.' + brand + '.com');
            if (!isOfficial) {
                findings.push("Contains protected brand name '" + brand + "' outside official company domain infrastructure.");
            }
        }
    }

    if ((domain.split('-').length - 1) > 3) {
        findings.push("Contains an abnormally high number of hyphens used to mask structural paths.");
    }

    const shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'adf.ly', 'lnkd.in'];
    if (shorteners.includes(domain)) {
        findings.push("⚠️ URL Obfuscation Vector: This uses a link shortener service. The true endpoint location remains masked until visited.");
    }

    const dangerousExtensions = ['.exe', '.scr', '.bat', '.apk', '.vbs', '.msi', '.cmd', '.zip', '.iso'];
    for (let j = 0; j < dangerousExtensions.length; j++) {
        if (pathname.endsWith(dangerousExtensions[j])) {
            findings.push("🚨 CRITICAL ALERT: Link directs straight to a terminal downloadable payload object (" + dangerousExtensions[j] + ").");
        }
    }

    return findings;
}

// Global output evaluation logic 
function processAndDisplayUrl(inputUrl) {
    try {
        const parsedUrl = new URL(inputUrl);
        const structuralWarnings = inspectUrlPathAndDomain(parsedUrl);

        // Clear marketing telemetry trackers parameters
        const trackingParams = ['fbclid', 'gclid', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'affiliate', 'ref'];
        for (let k = 0; k < trackingParams.length; k++) {
            parsedUrl.searchParams.delete(trackingParams[k]);
        }

        const sanitizedUrl = parsedUrl.toString();
        let reportHtml = '<h3>Security Vector Report</h3>';
        
        if (structuralWarnings.length > 0) {
            resultDiv.className = 'warning';
            reportHtml += '⚠️ <strong>Anomalies and Security Risks Flagged:</strong><ul>';
            for (let m = 0; m < structuralWarnings.length; m++) {
                reportHtml += '<li>' + structuralWarnings[m] + '</li>';
            }
            reportHtml += '</ul>';
        } else {
            resultDiv.className = 'clean';
            reportHtml += '✅ Structural analysis clears the link root domain and download signature framework.';
        }

        reportHtml += '<br><br><strong>Extracted/Sanitized URL (Trackers Cleared):</strong><div class="box">' + sanitizedUrl + '</div>';
        resultDiv.innerHTML = reportHtml;

    } catch (err) {
        resultDiv.className = 'warning';
        resultDiv.innerText = 'Error: The text extracted or pasted is not a valid complete link (must include https:// or http://). Text found: ' + inputUrl;
    }
}

// --- Submit Forms Listeners ---
urlForm.addEventListener('submit', function(e) {
    e.preventDefault();
    const inputUrl = document.getElementById('targetUrl').value.trim();
    resultDiv.style.display = 'block';
    resultDiv.className = 'box';
    resultDiv.innerText = 'Analyzing link infrastructure...';
    processAndDisplayUrl(inputUrl);
});

qrForm.addEventListener('submit', function(e) {
    e.preventDefault();
    const fileInput = document.getElementById('qrFile');
    if (fileInput.files.length === 0) return;

    resultDiv.style.display = 'block';
    resultDiv.className = 'box';
    resultDiv.innerText = 'Compressing image and decoding matrix data...';

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(event) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            // Fixed mobile resolution engine compressor
            // Limits maximum scale bounds to 500px to ensure lightning-fast image processing
            const maxDimension = 500;
            let width = img.width;
            let height = img.height;
            
            if (width > height) {
                if (width > maxDimension) {
                    height *= maxDimension / width;
                    width = maxDimension;
                }
            } else {
                if (height > maxDimension) {
                    width *= maxDimension / height;
                    height = maxDimension;
                }
            }
            
            canvas.width = width;
            canvas.height = height;
            ctx.drawImage(img, 0, 0, width, height);
            
            try {
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height);

                if (code && code.data) {
                    processAndDisplayUrl(code.data);
                } else {
                    resultDiv.className = 'warning';
                    resultDiv.innerText = '🚨 Scan Failed: Could not read a valid QR matrix pattern. Make sure the QR code is centered, well-lit, and not blurry.';
                }
            } catch (canvasErr) {
                resultDiv.className = 'warning';
                resultDiv.innerText = 'Security sandbox restriction: ' + canvasErr.message;
            }
        };
        img.src = event.target.result;
    };
    reader.readAsDataURL(file);
});
