# The Lost MC – Netlify kurulumu

Harici hesap (Firebase vb.) GEREKMEZ. Veriler Netlify Blobs'ta, giriş/yetki kontrolü Netlify Function'da tutulur.

1. Bu klasörü GitHub'a yükleyin (index.html, netlify.toml, package.json, netlify/ klasörü).
2. Netlify > Add new site > Import from Git > repoyu seçin. Build command boş, publish directory `.` kalsın.
3. Deploy bitince siteyi açın, İLK kayıt olan kişi otomatik **President** olur.

Not: Klasörü sürükle-bırak (Netlify Drop) ile yüklerseniz Functions çalışmaz; Git veya Netlify CLI (`netlify deploy --prod`) kullanın.
İsteğe bağlı: Site settings > Environment variables > `SESSION_SECRET` (rastgele uzun metin).
