const C="mv-shell-1";
self.addEventListener("install",e=>e.waitUntil(caches.open(C).then(c=>c.addAll(["/","/archive.html","/icon.svg"]))));
self.addEventListener("fetch",e=>{const u=new URL(e.request.url);if(e.request.method!=="GET"||u.pathname.startsWith("/api/"))return;
 e.respondWith(fetch(e.request).then(r=>{const k=r.clone();caches.open(C).then(c=>c.put(e.request,k));return r}).catch(()=>caches.match(e.request)))});
