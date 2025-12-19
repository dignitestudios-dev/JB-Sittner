    // Scripts for firebase and firebase messaging
    importScripts("https://www.gstatic.com/firebasejs/8.10.0/firebase-app.js");
    importScripts(
    "https://www.gstatic.com/firebasejs/8.10.0/firebase-messaging.js"
    );

    // Initialize the Firebase app in the service worker
    // "Default" Firebase configuration (prevents errors)
    const defaultConfig = {
    apiKey: true,
    projectId: true,
    messagingSenderId: true,
    appId: true,
    };
    const firebaseConfig = {
        apiKey: "AIzaSyCzOvI5pg2eP-R3VgT353AdhvERIe2thpA",
        authDomain: "jbst-dispatch-app-b62fd.firebaseapp.com",
        projectId: "jbst-dispatch-app-b62fd",
        storageBucket: "jbst-dispatch-app-b62fd.appspot.com",
        messagingSenderId: "883367538515",
        appId: "1:883367538515:web:43a35efb234a3e1be9bba6",
        measurementId: "G-YD03QBDEMJ",
    };

    firebase.initializeApp(firebaseConfig);

    // Retrieve firebase messaging
    const messaging = firebase.messaging();

    messaging.onBackgroundMessage((payload) => {
    const notificationTitle = payload.notification.title;
    const notificationOptions = {
        body: payload.notification.body,
        icon: payload.notification.image,
    };

    self.registration.showNotification(notificationTitle, notificationOptions);
    });