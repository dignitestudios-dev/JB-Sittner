import React, { useContext, useState } from "react";
import { LuBell } from "react-icons/lu";
import { MyContext } from "../../context/GlobalContext";
import {
  collection,
  db,
  getDocs,
  onSnapshot,
  query,
  updateDoc,
  where,
} from "../../firbase/FirebaseInit";

export default function Dropdown() {
  const {
    IsDropdownOpen,
    setIsDropdown,
    NotificationCount,
    setNotificationCount,
    Employee,
  } = useContext(MyContext);

  const handleDrop = async () => {
    try {
      setIsDropdown((prev) => !prev);
      const notificationsRef = collection(db, "notification");
      const querySnapshot = await getDocs(notificationsRef);
      
      // Start by updating the notifications in Firestore
      const updates = querySnapshot.docs.map(async (doc) => {
        const seenArray = doc.data()?.seen || [];
        const hasSeen = seenArray.some((user) => user.EmployeeId === Employee.id);
  
        if (!hasSeen) {
          const seenData = { EmployeeId: Employee.id };
          // Update Firestore to mark the notification as seen
          await updateDoc(doc.ref, { seen: [...seenArray, seenData] });
        }
      });
      
      // Wait for all Firestore updates to complete
      await Promise.all(updates);
  
      // Recalculate the unseen notifications for this user
      const deliveredNotifications = notifications.filter(
        (notification) => notification.status === "Delivered"
      );
      
      const unseenNotifications = deliveredNotifications.filter(
        (notification) =>
          !notification?.seen?.some((seen) => seen.EmployeeId === Employee.id)
      );
  
      // Update the counter
      const newNotificationCount = unseenNotifications.length;
      setNotificationCount(newNotificationCount);
      Cookies.set("notificationCount", newNotificationCount);
  
    } catch (error) {
      console.error("Error updating notifications: ", error);
    }
  };

  
 
  
  return (
    <>
      <button
        onClick={() => handleDrop()}
        className="w-[32px] h-[32px] flex items-center justify-center mr-5 relative right-0 border-2 bg-[#F2F3F4] border-transparent text-gray-800 rounded-[8px] hover:text-gray-400 focus:outline-none focus:text-gray-500 transition duration-150 ease-in-out"
        aria-label="Notifications"
      >
        <LuBell />
        {NotificationCount > 0 && (
          <span className="absolute -inset-2 object-right-top -mr-8">
            <div className="inline-flex items-center px-1.5 py-0.5 border-2 border-white rounded-full text-xs font-semibold leading-4 bg-[#EF5151] text-white">
              {NotificationCount > 0 ? NotificationCount : null}
            </div>
          </span>
        )}
      </button>
    </>
  );
}
