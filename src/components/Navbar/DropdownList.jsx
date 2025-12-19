import React, { useContext, useEffect, useRef, useState } from "react";
import { MyContext } from "../../context/GlobalContext";
import {
  addDoc,
  collection,
  db,
  doc,
  getDoc,
  getDocs,
  messaging,
  onSnapshot,
  query,
  setDoc,
  updateDoc,
} from "../../firbase/FirebaseInit";
import Cookies from "js-cookie";
import { toast } from "react-toastify";
import moment from "moment";
import "moment-timezone";
import { getToken, onMessage } from "firebase/messaging";
export default function DropdownList() {
  const {
    IsDropdownOpen,
    setIsDropdown,
    setNotificationCount,
    NotificationCount,
    Employee,
  } = useContext(MyContext);


  const [notifications, setNotifications] = useState([]);
  const [DevNotifications, setDevNotifications] = useState([]);
  const [UserRole, setUserRole] = useState("");
  const [loading, setLoading] = useState(true);
  const previousNotificationCount = useRef(NotificationCount);
  const DropdownRef = useRef(null);
  // Load previously triggered notifications from localStorage
  const triggeredNotifications = useRef(
    new Set(JSON.parse(localStorage.getItem("triggeredNotifications")) || [])
  );

  // Fetch notifications from Firestore
  const getNots = () => {
    const cookieData = Cookies.get("employe");
    const data = JSON.parse(cookieData || "{}");
    setUserRole(data?.role || "");
    const notificationsRef = collection(db, "notification");

    const unsubscribe = onSnapshot(notificationsRef, (querySnapshot) => {
      const now = moment.tz("America/Denver");
      const fetchedNotifications = [];
      querySnapshot.forEach((doc) => {
        const data = doc.data();
        const notificationDate = moment.tz(
          `${data.date} ${data.time}`,
          "MM/DD/YYYY h:mm A",
          "America/Denver"
        );
        if (
          notificationDate.isSameOrBefore(now) &&
          data.status === "Scheduled"
        ) {
          updateDoc(doc.ref, {
            status: "Delivered",
            seen: [],
          });
        }
        fetchedNotifications.push({ id: doc.id, ...data });
      });

      const sortedNotifications = fetchedNotifications.sort((a, b) => {
        const dateA = new Date(`${a.date} ${a.time}`);
        const dateB = new Date(`${b.date} ${b.time}`);
        return dateB - dateA;
      });

      setNotifications(sortedNotifications);
    });

    return unsubscribe;
  };

  useEffect(() => {
    const unsubscribe = getNots();
    const intervalId = setInterval(() => {
      getNots();
    }, 30000);

    return () => {
      clearInterval(intervalId);
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    const deliveredNotifications = notifications.filter(
      (notification) => notification.status === "Delivered"
    );
  
    // Get all unseen notifications for the current user
    const unseenNotifications = deliveredNotifications.filter(
      (notification) =>
        !notification?.seen?.some((seen) => seen.EmployeeId === Employee.id)
    );
  
    // Update the displayed notifications
    setDevNotifications(deliveredNotifications);
  
    // Calculate the new unseen notification count
    const newNotificationCount = unseenNotifications.length;
    Cookies.set("notificationCount", newNotificationCount);
  
    // Filter old notifications that are newer than the employee's creation date
    const oldNotificationCount = unseenNotifications.filter((notification) =>
      moment(notification.date + ", " + notification.time).isAfter(
        moment(Employee.createdat)
      )
    );
    
    // Update the notification count for the employee
    setNotificationCount(oldNotificationCount.length);
  
    // Show toast notifications for new unseen notifications
    if (
      unseenNotifications[0]?.title &&
      oldNotificationCount.length > 0 &&
      !triggeredNotifications.current.has(unseenNotifications[0]?.id) &&
      Employee.role === "user"
    ) {
      const newNotificationTitle =
        unseenNotifications[0]?.title || "New Notification";
  
      toast.success(
        newNotificationTitle.length > 16
          ? `${newNotificationTitle.slice(0, 16)}...`
          : newNotificationTitle,
        {
          position: "top-right",
          autoClose: 3000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
        }
      );
      
      // Mark notifications as triggered
      unseenNotifications.forEach((notss) => {
        triggeredNotifications.current.add(notss?.id);
        localStorage.setItem(
          "triggeredNotifications",
          JSON.stringify(Array.from(triggeredNotifications.current))
        );
        
        const notificationsRef = collection(db, "notification");
        const unsubscribe = onSnapshot(notificationsRef, (querySnapshot) => {
          querySnapshot.forEach((doc) => {
            const data = doc.data();
            if (data.notificationId == notss.notificationId) {
              const updatedToastIds = Array.from(
                new Set([...data.toast, Employee.id])
              );
              updateDoc(doc.ref, { toast: updatedToastIds });
            }
          });
        });
      });
    }
  
    // Keep track of the previous notification count
    previousNotificationCount.current = newNotificationCount;
  }, [notifications, Employee.id, Employee.createdat, Employee.role]);
  
  const toggleModal = () => {
    setIsDropdown(!IsDropdownOpen);
  };

  return (
    <>
      {IsDropdownOpen && (
        <div
          onClick={toggleModal}
          style={{ position: "fixed", top: "0px" }}
          className={` h-[350px]   transition-all duration-500  ${
            IsDropdownOpen
              ? "opacity-1 translate-y-11"
              : "opacity-0 translate-y-8"
          } lg:static  px-3 w-[300px] md:w-[400px] flex flex-col right-[7px] lg:right-[40px] gap-3 items-center justify-start py-0  `}
        >
          <div
            ref={DropdownRef}
            className={`fixed top-0 right-0 transition-all shadow-xl duration-200  ${
              IsDropdownOpen
                ? "opacity-1 translate-y-8"
                : "opacity-0 translate-y-8"
            } lg:static w-[100%] overflow-auto  scroll-box gap-3 rounded-[16px] px-5 py-5 h-full bg-[#FFFFFF]`}
          >
            <h3 className="text-base leading-[19px] font-bold">
              Notifications
            </h3>
            {DevNotifications.length === 0 ? (
              <p className="text-center text-gray-500 mt-4">
                No notifications available.
              </p>
            ) : (
              <ul className="max-w-md mt-4 divide-y divide-gray-200 dark:divide-gray-700">
                {DevNotifications.map((notification) => (
                  <>
                    {moment(
                      notification.date + ", " + notification.time
                    ).isAfter(moment(Employee.createdat)) && (
                      <li
                        key={notification.id}
                        className="pb-3 pt-3 sm:pb-4 mt-2 "
                      >
                        <div className="flex space-x-4 ">
                          <div className="flex-1 min-w-0">
                            <p className="text-[13px] font-bold">
                              {notification?.title}
                            </p>
                            <p className="text-[13px] text-[#909090] font-normal">
                              {notification.description &&
                              notification.description.length > 20
                                ? window.innerWidth <= 768
                                  ? notification.description.slice(0, 20) +
                                    "..."
                                  : notification.description.slice(0, 50) +
                                    "..."
                                : notification.description}
                            </p>
                          </div>
                          <div className="flex flex-col items-end">
                            <p className="text-xs text-[#717171] font-medium">
                              {notification.time}
                            </p>
                            <div className="inline-flex items-center justify-end text-base font-semibold text-gray-900">
                              <span className="">
                                {notification.seen === "pending" && (
                                  <div className="inline-flex items-center px-1.5 py-0.5 border-2 border-white rounded-full text-xs font-semibold leading-4 bg-[#EF5151] text-white">
                                    {notification.seen === "pending" ? "1" : ""}
                                  </div>
                                )}
                              </span>
                            </div>
                          </div>
                        </div>
                      </li>
                    )}
                  </>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </>
  );
}
