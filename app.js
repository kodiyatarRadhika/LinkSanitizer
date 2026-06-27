// Theme Toggle Engine
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

// Navigation Controllers
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

// Central Threat Scanner Engine
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
                findings.push("Contains brand name '" + brand + "' outside official company domain infrastructure.");
            }
        }
    }

    if ((domain.split('-').length - 1) > 3) {
        findings.push("Contains an abnormally high number of hyphens used to mask structural paths.");
    }

    const shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'adf.ly', 'lnkd.in'];
    if (shorteners.includes(domain)) {
        findings.push("⚠️ URL Obfuscation: Uses a link shortener. Hidden final location.");
    }

    const dangerousExtensions = ['.exe', '.scr', '.bat', '.apk', '.vbs', '.msi', '.cmd', '.zip', '.iso'];
    for (let j = 0; j < dangerousExtensions.length; j++) {
        if (pathname.endsWith(dangerousExtensions[j])) {
            findings.push("🚨 CRITICAL ALERT: Directly targets downloadable executable payload (" + dangerousExtensions[j] + ").");
        }
    }

    return findings;
}

function processAndDisplayUrl(inputUrl) {
    try {
        const parsedUrl = new URL(inputUrl);
        const structuralWarnings = inspectUrlPathAndDomain(parsedUrl);

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
            reportHtml += '✅ Structural analysis clears the link core framework.';
        }

        reportHtml += '<br><br><strong>Extracted & Sanitized URL:</strong><div class="box">' + sanitizedUrl + '</div>';
        resultDiv.innerHTML = reportHtml;

    } catch (err) {
        resultDiv.className = 'warning';
        resultDiv.innerText = 'Error: Valid complete web address required (including https://).';
    }
}

// Form Triggers
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
    resultDiv.innerText = 'Processing matrix data layer...';

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(event) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0, img.width, img.height);
            
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);

            if (code) {
                processAndDisplayUrl(code.data);
            } else {
                resultDiv.className = 'warning';
                resultDiv.innerText = '🚨 Error: Unable to read valid QR matrix coordinates.';
            }
        };
        img.src = event.target.result;
    };
    reader.readAsDataURL(file);
});

