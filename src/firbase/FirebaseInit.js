import { initializeApp } from "firebase/app";
import {
  getAuth,
  signInWithEmailAndPassword,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
} from "firebase/auth";
import {
  getFirestore,
  collection,
  getDocs,
  query,
  where,
  addDoc,
  updateDoc,
  doc,
  deleteDoc,
  onSnapshot,
  getDoc,
  orderBy,
  Timestamp,
  writeBatch,
  getCountFromServer ,
  setDoc
} from "firebase/firestore";
import {
  getStorage,
  ref,
  uploadBytesResumable,
  getDownloadURL,
  deleteObject ,
   list,
   updateMetadata ,
   listAll,
   getMetadata
} from "firebase/storage";
import { getMessaging } from "firebase/messaging";
const firebaseConfig = {
  apiKey: "AIzaSyCzOvI5pg2eP-R3VgT353AdhvERIe2thpA",
  authDomain: "jbst-dispatch-app-b62fd.firebaseapp.com",
  projectId: "jbst-dispatch-app-b62fd",
  storageBucket: "jbst-dispatch-app-b62fd.appspot.com",
  messagingSenderId: "883367538515",
  appId: "1:883367538515:web:43a35efb234a3e1be9bba6",
  measurementId: "G-YD03QBDEMJ",
};

const app = initializeApp(firebaseConfig);

const auth = getAuth(app);
const db = getFirestore();
const storage = getStorage();
const messaging = getMessaging(app);
export {
  messaging,
  auth,
  signInWithEmailAndPassword,
  onAuthStateChanged,
  db,
  collection,
  getDocs,
  query,
  where,
  addDoc,
  createUserWithEmailAndPassword,
  storage,
  ref,
  uploadBytesResumable,
  getDownloadURL,
  updateDoc,
  doc,
  deleteDoc,
  deleteObject,
  onSnapshot,
  getDoc,
   list,
   listAll,
   updateMetadata ,
   getMetadata,
   orderBy,
   Timestamp,
   writeBatch,
   getCountFromServer ,
   setDoc
};
