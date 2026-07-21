const fs = require('fs');
const path = require('path');

let cachedLogoDataUri = null;

/** شعار صفحة تسجيل الدخول — مضمّن base64 ليعمل مع طباعة blob URL */
function getPrintLogoDataUri() {
    if (cachedLogoDataUri !== null) return cachedLogoDataUri;
    const logoPath = path.join(__dirname, '../../frontend/assets/images/login-logo.png');
    try {
        if (fs.existsSync(logoPath)) {
            const buf = fs.readFileSync(logoPath);
            cachedLogoDataUri = `data:image/png;base64,${buf.toString('base64')}`;
        } else {
            cachedLogoDataUri = '';
        }
    } catch {
        cachedLogoDataUri = '';
    }
    return cachedLogoDataUri;
}

const PRINT_LOGO_CSS = `
                        .print-logo {
                            margin-bottom: 16px;
                        }
                        .print-logo img {
                            max-height: 90px;
                            max-width: 280px;
                            width: auto;
                            height: auto;
                            object-fit: contain;
                            object-position: center;
                            display: block;
                            margin: 0 auto;
                        }`;

function buildPrintHeaderHtml(title, permitNumberLabel, extraHtml = '') {
    const logo = getPrintLogoDataUri();
    const logoBlock = logo
        ? `<div class="print-logo"><img src="${logo}" alt="شعار محافظة الداخلية"></div>`
        : '';
    return `
                    <div class="header">
                        ${logoBlock}
                        <h1>${title}</h1>
                        <div class="permit-number">${permitNumberLabel}</div>
                        ${extraHtml}
                    </div>`;
}

module.exports = {
    getPrintLogoDataUri,
    PRINT_LOGO_CSS,
    buildPrintHeaderHtml
};
