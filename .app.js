if (notes.length === 0) {
      out += '- لم يتم اكتشاف مؤشرات هيورستيك خطيرة (نتيجة أولية). لكن هذا لا يعني أن الرابط آمن تماماً.\n';
    } else {
      notes.forEach((n, idx) => {
out += `${idx+1}. ${n}\n`;
    }
    out += \nتوصيات:\n• لا تفتح الرابط في جهازك الشخصي مباشرةً إن كنت تشك.\n• استخدم بيئة معزولة (VM) أو أدوات فحص مثل VirusTotal/URLVoid (باستخدام خادم وسيط إذا أردت التكامل).\n• يمكنك مشاركة الرابط مع الدعم عبر البريد أو الهاتف أدناه.\n;
    urlResults.innerText = out;
  });
});

/* ---------------------------
   File scan handler (SHA-256)
   --------------------------- */
async function sha256OfFile(file) {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hex;
}

scanFileBtn.addEventListener('click', async () => {
  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    fileResults.innerText = 'اختر ملفاً أولاً.';
    return;
  }
  
fileResults.innerText = 
`اسم الملف: ${file.name}
حجم الملف: ${file.size} بايت
نوع الملف: ${file.type || 'غير محدد'}

SHA-256: ${hex}


نصائح:
• يمكنك أخذ تجزئة SHA-256 ورفعها يدوياً على مواقع فحص الملفات (مثل VirusTotal).
• لا تشغّل الملفات المشتبه بها على جهاز رئيسي — استخدم بيئة معزولة.;
  } catch (err) {
    fileResults.innerText = 'حدث خطأ أثناء حساب التجزئة: ' + err;
  }
});

/* ---------------------------
   Domain/IP heuristics
   --------------------------- */
function simpleDomainChecks(s) {
  const notes = [];
  // clean
  const t = s.trim();
  // IP?
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    notes.push('النص يبدو كعنوان IP. تحقق من كونها IP معروفة/متوقعة.');
    return notes;
  }
  // basic domain pattern
  if (!/^[a-zA-Z0-9\-.]{1,253}\.[a-zA-Z]{2,63}$/.test(t)) {
    notes.push('لا يبدو كنطاق صالح (صيغة غير نمطية).');
    return notes;
  }
  const parts = t.split('.');
  if (parts.length < 2) notes.push('النطاق قصير جداً.');
  if (t.length > 60) notes.push('النطاق طويل نسبيًا — تحقق من وجود تقاطر أو محاولات تشابه.');
  // check numeric-domains
  if (/[0-9]{6,}/.test(t)) notes.push('وجود سلسلة أرقام طويلة داخل النطاق — قد تكون علامة على دومين مولَّد تلقائياً.');
  return notes;
}

scanDomainBtn.addEventListener('click', () => {
  const raw = domainInput.value.trim();
  if (!raw) { domainResults.innerText = 'أدخل دومين أو IP للفحص.'; return; }
  domainResults.innerText = 'جارٍ تحليل...';
  setTimeout(() => {
    const notes = simpleDomainChecks(raw);
    let out = المدخل: ${raw}\n\n;
    if (notes.length === 0) {
      out += '- لم يتم اكتشاف مؤشرات خطأ فورية (فحص هيورستيك بسيط).\n';
    } else {
      notes.forEach((n, i) => out += ${i+1}. ${n}\n);
    }
    out += \nتوصيات:\n• لا تعتمد على هذا الفحص وحده — استخدم خدمات WHOIS, DNS lookup, RBL lists عبر خادم آمن إن أردت تحليل أعمق.\n;
    domainResults.innerText = out;
  }, 700);
});

/* ---------------------------
   End of file
   --------------------------- */
   