import React, { useContext, useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { collection, db, onSnapshot, query } from "../../firbase/FirebaseInit";
import { MyContext } from "../../context/GlobalContext";
import Loader from "../../global/Loader";

export default function NotificationList() {
  const [Notification, SetNotification] = useState([]);
  const { setLoader, loader, RealTimeData } = useContext(MyContext);
  const getNotification = () => {
    const employeesRef = collection(db, "notification");
    const employeeQuery = query(employeesRef);
    setLoader(true);
    const unsubscribe = onSnapshot(
      employeeQuery,
      (querySnapshot) => {
        const notificationData = querySnapshot.docs.map((doc) => ({
          docId: doc.id,
          ...doc.data(),
        }));
        const sortedNotifications = notificationData.sort((a, b) => {
          const dateA = new Date(`${a.date} ${a.time}`);
          const dateB = new Date(`${b.date} ${b.time}`);
          return dateB - dateA;
        });

        SetNotification(sortedNotifications);
        setLoader(false);
      },
      (error) => {
        console.error("Error fetching notifications: ", error);
        setLoader(false);
      }
    );

    return unsubscribe;
  };

  useEffect(() => {
    const unsubscribe = getNotification();
    return () => unsubscribe();
  }, [RealTimeData]);

  return (
    <div className="bg-[#FFFFFF] border rounded-[10px] h-[70vh] scroll-box  overflow-auto border-[#E4E4E4] mt-6 px-3 py-3 lg:py-5 lg:px-5">
      <div className="relative overflow-x-auto">
        {loader ? (
          <Loader />
        ) 
        : Notification.length === 0 ? (
          <div className="text-center text-gray-500 mt-4">
            No Notifications items available.
          </div>
        ) : (
          <table className="w-full text-sm text-left  text-gray-500 dark:text-gray-400">
            <thead className="text-xs text-[#787F8C] uppercase bg-[#F3F5F7]">
              <tr>
                <th scope="col" className="px-6 py-3 rounded-s-lg">
                  Title
                </th>
                <th scope="col" className="px-6 py-3">
                  Description
                </th>
                <th scope="col" className="px-6 py-3 rounded-e-lg">
                  Status
                </th>
                <th scope="col" className="px-6 py-3  rounded-e-lg">
                  <span className="flex xl:hidden">Action</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {Notification?.map((item, i) => (
                <tr key={i} className="bg-white  border-b-2 border-[#F4F4F4]  ">
                  <th
                    scope="row"
                    className="px-6 py-10  text-gray-900 whitespace-nowrap text-base font-normal"
                  >
                    {item.title}
                  </th>
                  <td className="px-6 py-10 text-[#18181880]  text-base font-normal">
                    <p className="sm:w-[200px] overflow-auto text-nowrap lg:text-wrap lg:w-[550px]">
                      {item.description}
                    </p>
                  </td>
                  <td className="px-6 py-10">
                    <div
                      className={` ${
                        item.status == "Scheduled"
                          ? "bg-[#FF99001F] text-[#FF9900]"
                          : "text-[#41C54E] bg-[#41C54E26]"
                      } w-[120px] md:w-[100px] text-center  text-xs font-bold me-2 px-4 py-2 rounded-full`}
                    >
                      {item.status == "Scheduled" ? "Scheduled" : "Delivered"}
                    </div>
                  </td>
                  {item.status == "Scheduled" && (
                    <td className="px-6 py-10">
                      <NavLink
                        to={"/editnotification"}
                        state={{ data: item }}
                        className="bg-transparent"
                      >
                        <img
                          src="/whiteedit.png"
                          className="w-5 lg:w-5"
                          alt=""
                          srcset=""
                        />
                      </NavLink>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
