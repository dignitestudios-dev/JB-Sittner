    const cacheName = 'app-cache';
    const cacheVersion = 0;
    const cacheFullName = `${cacheName}-${cacheVersion}`;

    self.addEventListener('install', async (e) => {
    const cache = await caches.open(cacheFullName);
    await cache.addAll([
        '/index.html',
        '/src/index.scss',
        '/src/assets/images/favicon.png',
        '/src/assets/images/logo-color.png',
        '/src/assets/images/logo-solid.png',
    ]);
    });

    self.addEventListener('activate', async (e) => {
    const cacheNames = await caches.keys();
    await Promise.all(
        cacheNames.map(async (name) => {
        if (name !== cacheFullName) {
            await caches.delete(name);
        }
        })
    );
    });

    self.addEventListener('fetch', (e) => {
    e.respondWith(
        caches.match(e.request).then((res) => (res ? res : fetch(e.request)))
    );
    });

    // navigator.serviceWorker.register('/firebase-messaging-sw.js')
      